import * as fs from "fs";
import * as path from "path";
import { Backend } from "./backend";
import { BIP110, ChainProfile } from "./chain";
import { Descriptor, walletFingerprints } from "./descriptor";

export type Coin = {
    txid: string;
    vout: number;
    value: number;
    address: string;
    branch: number;
    index: number;
    confirmed: boolean;
    blockTime?: number;
};

export type ScanResult = {
    coins: Coin[];
    // Highest index with on-chain history per branch, -1 when none.
    lastUsed: number[];
    addressesChecked: number;
};

export type SavedScan = ScanResult & {
    file: string;
    backend: string;
    scannedAt: string;
};

export type ScanOptions = {
    gapLimit?: number;
    concurrency?: number;
    onProgress?: (message: string) => void;
};

const CSV_HEADER = "Date (UTC),Output,Address,Label,Value";
export const SCAN_FILE_PREFIX = "delete_later_";

export function outpoint(coin: { txid: string; vout: number }): string {
    return `${coin.txid}:${coin.vout}`;
}

export function formatBtc(sats: number): string {
    return `${Math.floor(sats / 1e8)}.${String(sats % 1e8).padStart(8, "0")}`;
}

async function collectUnspent(descriptor: Descriptor, backend: Backend, branch: number, index: number): Promise<Coin[]> {
    const derived = descriptor.derive(branch, index);
    const utxos = await backend.listUnspent(derived.address, derived.output);
    return utxos.map(u => ({ ...u, address: derived.address, branch, index }));
}

// Walks one branch from `start` until `gapLimit` consecutive addresses have no history.
// A descriptor of single keys has one address, so only index 0 is checked.
async function scanBranch(
    descriptor: Descriptor, backend: Backend, branch: number, start: number, options: Required<Omit<ScanOptions, "onProgress">> & ScanOptions,
): Promise<{ coins: Coin[]; lastUsed: number; checked: number }> {
    const coins: Coin[] = [];
    let lastUsed = start - 1;
    let emptyRun = 0;
    let checked = 0;
    let index = start;
    const step = descriptor.branchStep(branch);
    const gapLimit = descriptor.ranged ? options.gapLimit : 1;
    while (emptyRun < gapLimit) {
        const batch = Array.from({ length: descriptor.ranged ? options.concurrency : 1 }, (_, i) => index + i);
        options.onProgress?.(`Checking /${step}/${batch[0]}-${batch[batch.length - 1]} (gap ${emptyRun}/${options.gapLimit}, ${coins.length} coins so far)`);
        const used = await Promise.all(batch.map(i => {
            const derived = descriptor.derive(branch, i);
            return backend.hasHistory(derived.address, derived.output);
        }));
        const usedIndexes: number[] = [];
        for (let i = 0; i < batch.length && emptyRun < gapLimit; i++) {
            checked++;
            if (used[i]) {
                emptyRun = 0;
                lastUsed = batch[i];
                usedIndexes.push(batch[i]);
            } else {
                emptyRun++;
            }
        }
        for (const found of await Promise.all(usedIndexes.map(i => collectUnspent(descriptor, backend, branch, i)))) {
            coins.push(...found);
        }
        index += batch.length;
        if (!descriptor.ranged) break;
    }
    return { coins, lastUsed, checked };
}

// True when one of the first `gapLimit` receive addresses has on-chain history. Used to tell
// which script type a bare key was used with.
export async function hasReceiveHistory(descriptor: Descriptor, backend: Backend, gapLimit = 20, concurrency = 5): Promise<boolean> {
    if (!descriptor.ranged) gapLimit = 1;
    for (let start = 0; start < gapLimit; start += concurrency) {
        const batch = Array.from({ length: Math.min(concurrency, gapLimit - start) }, (_, i) => start + i);
        const used = await Promise.all(batch.map(i => {
            const derived = descriptor.derive(0, i);
            return backend.hasHistory(derived.address, derived.output);
        }));
        if (used.some(Boolean)) return true;
    }
    return false;
}

// Full scan when `previous` is undefined. Otherwise a refresh: re-checks the addresses
// that held coins last time, then continues the gap scan after the last used index.
export async function scanDescriptor(
    descriptor: Descriptor, backend: Backend, options: ScanOptions = {}, previous?: ScanResult,
): Promise<ScanResult> {
    const settings = { gapLimit: options.gapLimit ?? 20, concurrency: options.concurrency ?? 5, ...options };
    if (!Number.isSafeInteger(settings.gapLimit) || settings.gapLimit < 1) throw new Error("gap limit must be a positive integer");
    // A single-key descriptor has one address, so a refresh is the same as a full scan.
    if (!descriptor.ranged) previous = undefined;
    const coins: Coin[] = [];
    const lastUsed: number[] = [];
    let addressesChecked = 0;

    if (previous) {
        const known = new Map<string, { branch: number; index: number }>();
        for (const coin of previous.coins) known.set(`${coin.branch}/${coin.index}`, coin);
        options.onProgress?.(`Re-checking ${known.size} address(es) that held coins in the last scan`);
        const refreshed = await Promise.all([...known.values()].map(k => collectUnspent(descriptor, backend, k.branch, k.index)));
        refreshed.forEach(found => coins.push(...found));
        addressesChecked += known.size;
    }

    for (let branch = 0; branch < descriptor.branches; branch++) {
        const start = previous ? (previous.lastUsed[branch] ?? -1) + 1 : 0;
        const result = await scanBranch(descriptor, backend, branch, start, settings);
        coins.push(...result.coins);
        lastUsed.push(Math.max(result.lastUsed, previous?.lastUsed[branch] ?? -1));
        addressesChecked += result.checked;
    }

    const unique = new Map<string, Coin>();
    for (const coin of coins) unique.set(outpoint(coin), coin);
    const sorted = [...unique.values()].sort((a, b) => a.branch - b.branch || a.index - b.index || a.txid.localeCompare(b.txid) || a.vout - b.vout);
    return { coins: sorted, lastUsed, addressesChecked };
}

function csvDate(blockTime?: number): string {
    return blockTime === undefined ? "" : new Date(blockTime * 1000).toISOString().slice(0, 19).replace("T", " ");
}

// Same five-column format as Sparrow's UTXO export, so the file also works as
// `utxo_file` for the config.toml flow. The "#" header lines record which
// descriptor owns the coins; the label column holds "<branch>/<index>".
export function formatScanCsv(chain: ChainProfile, descriptor: Descriptor, backend: string, scannedAt: string, scan: ScanResult): string {
    const lines = [
        "# split-bip110 scan. Safe to delete; it only speeds up the next scan of this descriptor.",
        `# chain: ${chain.key}`,
        `# descriptor: ${descriptor.text}`,
        `# descriptor-id: ${descriptor.id}`,
        `# backend: ${backend}`,
        `# scanned-at: ${scannedAt}`,
        `# last-used: ${scan.lastUsed.join(",")}`,
        CSV_HEADER,
        ...scan.coins.map(c =>
            `${csvDate(c.blockTime)},${outpoint(c)},${c.address},${c.branch}/${c.index}${c.confirmed ? "" : " unconfirmed"},${formatBtc(c.value)}`),
    ];
    return lines.join("\n") + "\n";
}

export function parseScanCsv(chain: ChainProfile, descriptor: Descriptor, content: string, file: string): SavedScan {
    const header = new Map<string, string>();
    const coins: Coin[] = [];
    for (const raw of content.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line === CSV_HEADER) continue;
        if (line.startsWith("#")) {
            const match = /^#\s*([a-z-]+):\s*(.*)$/.exec(line);
            if (match) header.set(match[1], match[2]);
            continue;
        }
        const [date, out, address, label, value] = line.split(",");
        const outMatch = /^([0-9a-f]{64}):(\d+)$/.exec(out ?? "");
        const labelMatch = /^(\d+)\/(\d+)( unconfirmed)?$/.exec(label ?? "");
        if (!outMatch || !labelMatch || !/^\d+\.\d{8}$/.test(value ?? "")) throw new Error(`Malformed line in ${file}: ${line}`);
        const branch = Number(labelMatch[1]);
        const index = Number(labelMatch[2]);
        if (branch >= descriptor.branches || descriptor.derive(branch, index).address !== address) {
            throw new Error(`${file} lists ${address}, which this descriptor does not derive at ${branch}/${index}`);
        }
        const [whole, fraction] = value.split(".");
        coins.push({
            txid: outMatch[1],
            vout: Number(outMatch[2]),
            value: Number(whole) * 1e8 + Number(fraction),
            address,
            branch,
            index,
            confirmed: !labelMatch[3],
            blockTime: date ? Date.parse(`${date.replace(" ", "T")}Z`) / 1000 : undefined,
        });
    }
    if (header.get("descriptor-id") !== descriptor.id) throw new Error(`${file} belongs to a different descriptor`);
    // Files from before the Bitcoin step have no chain header and are BIP110 scans.
    if ((header.get("chain") ?? BIP110.key) !== chain.key) throw new Error(`${file} is a scan of another chain`);
    const lastUsed = (header.get("last-used") ?? "").split(",").map(Number);
    if (lastUsed.length !== descriptor.branches || lastUsed.some(n => !Number.isSafeInteger(n) || n < -1)) {
        throw new Error(`${file} has an invalid last-used header`);
    }
    return {
        file,
        backend: header.get("backend") ?? "unknown",
        scannedAt: header.get("scanned-at") ?? "unknown",
        coins,
        lastUsed,
        addressesChecked: 0,
    };
}

function scanFilePattern(chain: ChainProfile, descriptor: Descriptor): RegExp {
    return new RegExp(`^${SCAN_FILE_PREFIX}${chain.scanTag}[0-9a-f-]+_${descriptor.id}_\\d{8}T\\d{6}Z(?:-\\d+)?\\.csv$`);
}

// Scan files are never overwritten: each scan gets a new, timestamped file.
export function findLatestScan(directory: string, chain: ChainProfile, descriptor: Descriptor): { scan?: SavedScan; errors: string[] } {
    const pattern = scanFilePattern(chain, descriptor);
    let names: string[];
    try { names = fs.readdirSync(directory).filter(name => pattern.test(name)); }
    catch { return { errors: [] }; }
    // Newest first: by timestamp, then by the "-N" suffix used when two scans share a second.
    const key = (name: string) => {
        const match = /_(\d{8}T\d{6}Z)(?:-(\d+))?\.csv$/.exec(name)!;
        return { stamp: match[1], suffix: Number(match[2] ?? 0) };
    };
    names.sort((a, b) => {
        const ka = key(a), kb = key(b);
        return kb.stamp.localeCompare(ka.stamp) || kb.suffix - ka.suffix;
    });
    const errors: string[] = [];
    for (const name of names) {
        const file = path.join(directory, name);
        try {
            return { scan: parseScanCsv(chain, descriptor, fs.readFileSync(file, "utf8"), file), errors };
        } catch (error) {
            errors.push(error instanceof Error ? error.message : String(error));
        }
    }
    return { errors };
}

export function writeScanFile(directory: string, chain: ChainProfile, descriptor: Descriptor, backend: string, scan: ScanResult, now = new Date()): string {
    const scannedAt = now.toISOString();
    const stamp = scannedAt.replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
    const base = `${SCAN_FILE_PREFIX}${chain.scanTag}${walletFingerprints(descriptor)}_${descriptor.id}_${stamp}`;
    const content = formatScanCsv(chain, descriptor, backend, scannedAt, scan);
    fs.mkdirSync(directory, { recursive: true });
    for (let attempt = 0; attempt < 100; attempt++) {
        const file = path.join(directory, `${base}${attempt === 0 ? "" : `-${attempt}`}.csv`);
        try {
            fs.writeFileSync(file, content, { flag: "wx", mode: 0o600 });
            return file;
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
    }
    throw new Error(`Could not find a free file name for ${base}.csv`);
}
