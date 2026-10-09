import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";
import { Transaction } from "bitcoinjs-lib";
import { assertChain, Backend, ElectrumBackend, EsploraBackend, Outspend } from "./wizard/backend";
import { BIP110, BITCOIN } from "./wizard/chain";

// Checks whether Bitcoin (BTC) transactions or coins made after the split can be copied to the BIP110 chain:
// every missing ancestor is traced back to outputs the fork already has, and those
// outputs must still be unspent there. Nothing is broadcast.

const TXID = /^[0-9a-f]{64}$/;

export type Input = { txid: string; vout: number };
export type MissingTx = { txid: string; rawHex: string; inputs: Input[]; coinbase: boolean };
type RequiredInput = { spendingTx: string; input: Input };

export type CopyBlocker =
    | { kind: "spent-input"; spendingTx: string; input: Input; spentBy: string; confirmed?: boolean }
    | { kind: "missing-coinbase"; txid: string };

export class CopyImpossibleError extends Error {
    constructor(readonly blocker: CopyBlocker) {
        super(blocker.kind === "spent-input" ?
            `${blocker.confirmed ? "Cannot be copied to the current BIP110 chain" : "Blocked for now by a BIP110 mempool transaction"}: ` +
            `${blocker.spendingTx} needs ${blocker.input.txid}:${blocker.input.vout}, which is already spent there by ${blocker.spentBy}` :
            `Cannot be copied to BIP110: it descends from Bitcoin block reward ${blocker.txid}, mined after the split`);
        this.name = "CopyImpossibleError";
    }
}

export type TraceSources = {
    getBitcoinRaw(txid: string): Promise<string>;
    forkHas(txid: string): Promise<boolean>;
    getForkOutspend(txid: string, vout: number): Promise<Outspend>;
};

export type TraceResult = {
    root: string;
    // Parents first; the root is last when it is missing.
    missing: MissingTx[];
    alreadyOnFork: string[];
    checked: number;
};

// Walks the root's ancestors breadth first until each branch reaches a transaction the fork has,
// then checks that the outputs the copy needs are still unspent on the fork.
export async function traceMissingParents(
    root: string,
    sources: TraceSources,
    options: { concurrency?: number; maxTransactions?: number; onProgress?: (message: string) => void } = {},
): Promise<TraceResult> {
    if (!TXID.test(root)) throw new Error("Transaction ID must be a 64-character lowercase hex txid");
    const concurrency = options.concurrency ?? 4;
    const maxTransactions = options.maxTransactions ?? 5000;
    if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 32) throw new Error("concurrency must be 1-32");
    if (!Number.isSafeInteger(maxTransactions) || maxTransactions < 1) throw new Error("maxTransactions must be positive");

    const missing = new Map<string, MissingTx>();
    const present = new Set<string>();
    const seen = new Set<string>();
    const queue = [root];
    const discovered = new Set(queue);
    const requiredBy = new Map<string, RequiredInput[]>();
    const checkedOutpoints = new Set<string>();
    let lastProgress = 0;

    // Missing transactions the root still depends on. A branch drops out once the fork has it.
    function requiredTransactions(): Set<string> {
        const required = new Set<string>();
        const stack = [root];
        while (stack.length > 0) {
            const txid = stack.pop()!;
            if (present.has(txid) || required.has(txid)) continue;
            required.add(txid);
            for (const input of missing.get(txid)?.inputs ?? []) stack.push(input.txid);
        }
        return required;
    }

    function recordInputs(tx: MissingTx): void {
        for (const input of tx.inputs) {
            const consumers = requiredBy.get(input.txid) ?? [];
            consumers.push({ spendingTx: tx.txid, input });
            requiredBy.set(input.txid, consumers);
        }
    }

    // Outputs of fork transactions that a missing transaction spends.
    function knownBoundary(): RequiredInput[] {
        const items: RequiredInput[] = [];
        for (const [parent, consumers] of requiredBy) {
            if (present.has(parent)) items.push(...consumers);
        }
        return items;
    }

    async function checkForkSpends(items: RequiredInput[], refresh = false): Promise<void> {
        let required = requiredTransactions();
        const unique = new Map<string, RequiredInput>();
        for (const item of items) {
            const outpoint = `${item.input.txid}:${item.input.vout}`;
            if (required.has(item.spendingTx) && (refresh || !checkedOutpoints.has(outpoint))) unique.set(outpoint, item);
        }
        const entries = [...unique];
        if (entries.length >= 100) options.onProgress?.(`Checking ${entries.length} required outputs on BIP110...`);
        for (let i = 0; i < entries.length; i += concurrency) {
            const results = await Promise.all(entries.slice(i, i + concurrency).map(async ([outpoint, item]) => ({
                outpoint, item, result: await sources.getForkOutspend(item.input.txid, item.input.vout),
            })));
            for (const { outpoint, item, result } of results) {
                if (!required.has(item.spendingTx)) continue;
                if (result.spent) {
                    // The fork spent it with the same transaction: it was already copied, not a conflict.
                    if (result.txid === item.spendingTx) {
                        if (!await sources.forkHas(item.spendingTx)) {
                            throw new Error(`BIP110 says ${item.spendingTx} spent ${outpoint}, but cannot find that transaction; retry when its indexer catches up`);
                        }
                        present.add(item.spendingTx);
                        missing.delete(item.spendingTx);
                        required = requiredTransactions();
                        checkedOutpoints.add(outpoint);
                        options.onProgress?.(`${item.spendingTx} is already on BIP110`);
                        continue;
                    }
                    throw new CopyImpossibleError({ kind: "spent-input", spendingTx: item.spendingTx,
                        input: item.input, spentBy: result.txid ?? "unknown", confirmed: result.confirmed });
                }
                checkedOutpoints.add(outpoint);
            }
        }
    }

    while (queue.length > 0 && !present.has(root)) {
        if (seen.size >= maxTransactions) {
            throw new Error(`Checked ${maxTransactions} transactions without reaching BIP110 on every branch; raise --max-transactions`);
        }
        const batch = queue.splice(0, Math.min(concurrency, maxTransactions - seen.size));
        const results = await Promise.all(batch.map(async txid => {
            if (await sources.forkHas(txid)) return { txid, present: true as const };
            const rawHex = await sources.getBitcoinRaw(txid);
            let tx: Transaction;
            try { tx = Transaction.fromHex(rawHex); }
            catch { throw new Error(`Cannot decode Bitcoin transaction ${txid}`); }
            if (tx.getId() !== txid) throw new Error(`Bitcoin server returned the wrong transaction for ${txid}`);
            const coinbase = tx.isCoinbase();
            const inputs = coinbase ? [] : tx.ins.map(input => ({
                txid: Buffer.from(input.hash).reverse().toString("hex"), vout: input.index,
            }));
            return { txid, present: false as const, tx: { txid, rawHex, inputs, coinbase } };
        }));
        let missingCoinbase: string | undefined;
        for (const result of results) {
            seen.add(result.txid);
            if (result.present) {
                present.add(result.txid);
                continue;
            }
            missing.set(result.txid, result.tx);
            if (result.tx.coinbase) missingCoinbase = result.txid;
            recordInputs(result.tx);
            for (const input of result.tx.inputs) {
                if (!discovered.has(input.txid)) {
                    discovered.add(input.txid);
                    queue.push(input.txid);
                }
            }
        }
        await checkForkSpends(knownBoundary());
        if (missingCoinbase && requiredTransactions().has(missingCoinbase)) {
            throw new CopyImpossibleError({ kind: "missing-coinbase", txid: missingCoinbase });
        }
        if (seen.size - lastProgress >= 10 || queue.length === 0) {
            options.onProgress?.(`Checked ${seen.size} transactions: ${missing.size} missing, ${present.size} already on BIP110, ${queue.length} queued`);
            lastProgress = seen.size;
        }
    }

    function orderedMissing(): MissingTx[] {
        const ordered: MissingTx[] = [];
        const visiting = new Set<string>();
        const visited = new Set<string>();
        function visit(txid: string): void {
            if (visited.has(txid) || present.has(txid)) return;
            if (visiting.has(txid)) throw new Error(`Cycle in transaction graph at ${txid}`);
            const tx = missing.get(txid);
            if (!tx) throw new Error(`Missing trace result for ${txid}`);
            visiting.add(txid);
            for (const input of tx.inputs) visit(input.txid);
            visiting.delete(txid);
            visited.add(txid);
            ordered.push(tx);
        }
        visit(root);
        return ordered;
    }

    // Check every boundary output once more: the fork may have moved on while the trace ran.
    const boundary = new Map<string, RequiredInput>();
    for (const tx of orderedMissing()) {
        for (const input of tx.inputs) {
            if (present.has(input.txid)) boundary.set(`${input.txid}:${input.vout}`, { spendingTx: tx.txid, input });
        }
    }
    await checkForkSpends([...boundary.values()], true);
    return { root, missing: orderedMissing(), alreadyOnFork: [...present].sort(), checked: seen.size };
}

export type Target = { txid: string; vout?: number };

export function parseTargets(values: string[]): Target[] {
    const targets: Target[] = [];
    const keys = new Set<string>();
    for (const value of values.flatMap(v => v.split(/[\s,]+/)).filter(Boolean)) {
        const match = /^([0-9a-fA-F]{64})(?::(\d{1,10}))?$/.exec(value);
        if (!match || (match[2] !== undefined && Number(match[2]) > 0xffffffff)) {
            throw new Error(`Not a txid or txid:vout: ${value}`);
        }
        const target = { txid: match[1].toLowerCase(), vout: match[2] === undefined ? undefined : Number(match[2]) };
        const key = label(target);
        if (!keys.has(key)) targets.push(target);
        keys.add(key);
    }
    if (targets.length === 0) throw new Error("Give at least one txid or txid:vout");
    return targets;
}

function label(target: Target): string {
    return target.vout === undefined ? target.txid : `${target.txid}:${target.vout}`;
}

export type Verdict =
    | { status: "on-fork"; target: Target; spentBy?: string; confirmed?: boolean }
    | { status: "copyable"; target: Target; trace: TraceResult }
    | { status: "blocked"; target: Target; blocker: CopyBlocker; message: string }
    | { status: "error"; target: Target; message: string };

export async function checkTarget(
    target: Target,
    sources: TraceSources,
    options: { concurrency?: number; maxTransactions?: number; onProgress?: (message: string) => void } = {},
): Promise<Verdict> {
    try {
        if (await sources.forkHas(target.txid)) {
            if (target.vout === undefined) return { status: "on-fork", target };
            const outspend = await sources.getForkOutspend(target.txid, target.vout);
            return outspend.spent ?
                { status: "on-fork", target, spentBy: outspend.txid ?? "unknown", confirmed: outspend.confirmed } :
                { status: "on-fork", target };
        }
        if (target.vout !== undefined) {
            const tx = Transaction.fromHex(await sources.getBitcoinRaw(target.txid));
            if (target.vout >= tx.outs.length) throw new Error(`Bitcoin transaction ${target.txid} has no output ${target.vout}`);
        }
        return { status: "copyable", target, trace: await traceMissingParents(target.txid, sources, options) };
    } catch (error) {
        if (error instanceof CopyImpossibleError) return { status: "blocked", target, blocker: error.blocker, message: error.message };
        return { status: "error", target, message: error instanceof Error ? error.message : String(error) };
    }
}

// One parent-first order for every copyable target, each transaction once.
export function combinedSendOrder(verdicts: Verdict[]): MissingTx[] {
    const order: MissingTx[] = [];
    const added = new Set<string>();
    for (const verdict of verdicts) {
        if (verdict.status !== "copyable") continue;
        for (const tx of verdict.trace.missing) {
            if (!added.has(tx.txid)) order.push(tx);
            added.add(tx.txid);
        }
    }
    return order;
}

export type BtcToBip110Options = {
    forkEsplora?: string;
    btcEsplora?: string;
    btcElectrum?: string;
    electrumSelfSigned?: boolean;
    concurrency: number;
    maxTransactions: number;
    outputDir: string;
};

export async function runBtcToBip110(values: string[], options: BtcToBip110Options): Promise<void> {
    const targets = parseTargets(values);
    const fork = new EsploraBackend(options.forkEsplora ?? BIP110.defaultEsplora);
    const bitcoin: Backend = options.btcElectrum ?
        await ElectrumBackend.connect(options.btcElectrum, { allowSelfSigned: options.electrumSelfSigned }) :
        new EsploraBackend(options.btcEsplora ?? BITCOIN.defaultEsplora);
    try {
        await assertChain(fork, BIP110);
        await assertChain(bitcoin, BITCOIN);
        console.log(chalk.dim(`BIP110: ${fork.label}  Bitcoin: ${bitcoin.label}`));

        const sources: TraceSources = {
            getBitcoinRaw: txid => bitcoin.getRawTransaction(txid),
            forkHas: txid => fork.hasTransaction(txid),
            getForkOutspend: (txid, vout) => fork.outspend(txid, vout),
        };
        const verdicts: Verdict[] = [];
        for (const target of targets) {
            console.log(`\n${chalk.bold(label(target))}`);
            const verdict = await checkTarget(target, sources, {
                concurrency: options.concurrency, maxTransactions: options.maxTransactions,
                onProgress: message => console.log(chalk.dim(`  ${message}`)),
            });
            verdicts.push(verdict);
            printVerdict(verdict);
        }

        const order = combinedSendOrder(verdicts);
        const counts = (status: Verdict["status"]) => verdicts.filter(v => v.status === status).length;
        console.log(`\n${counts("on-fork")} already on BIP110, ${counts("copyable")} can be copied, ` +
            `${counts("blocked")} cannot be copied, ${counts("error")} failed.`);
        if (order.length > 0) {
            const dir = writeReport(verdicts, order, options.outputDir, fork.label, bitcoin.label);
            console.log(`Wrote ${order.length} transactions in parent-first order to ${dir}`);
            console.log(chalk.dim("Nothing was broadcast. Review the transactions before sending them to BIP110 yourself."));
        }
        if (counts("error") > 0) process.exitCode = 1;
        else if (counts("blocked") > 0) process.exitCode = 2;
    } finally {
        fork.close();
        bitcoin.close();
    }
}

function printVerdict(verdict: Verdict): void {
    switch (verdict.status) {
        case "on-fork":
            if (verdict.spentBy) {
                console.log(chalk.yellow(`  Already on BIP110, but spent there by ${verdict.spentBy}${verdict.confirmed === false ? " (mempool)" : ""}`));
            } else {
                console.log(chalk.green(`  Already on BIP110${verdict.target.vout === undefined ? "" : " and unspent"}: nothing to copy`));
            }
            break;
        case "copyable": {
            const ancestors = verdict.trace.missing.length - 1;
            console.log(chalk.green(`  Can be copied to BIP110: ${verdict.trace.missing.length} transaction${verdict.trace.missing.length === 1 ? "" : "s"} to send` +
                (ancestors > 0 ? ` (${ancestors} missing ancestor${ancestors === 1 ? "" : "s"} first)` : "")));
            break;
        }
        case "blocked":
            console.log(chalk.red(`  ${verdict.message}`));
            break;
        case "error":
            console.log(chalk.red(`  Check failed: ${verdict.message}`));
            break;
    }
}

function writeReport(verdicts: Verdict[], order: MissingTx[], outputDir: string, forkLabel: string, bitcoinLabel: string): string {
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
    const dir = path.resolve(outputDir, `btc-to-bip110-${stamp}`);
    fs.mkdirSync(dir, { mode: 0o700 });
    const report = {
        createdAt: new Date().toISOString(),
        bip110: forkLabel,
        bitcoin: bitcoinLabel,
        targets: verdicts.map(v => ({
            target: label(v.target),
            status: v.status,
            ...(v.status === "on-fork" && v.spentBy ? { spentBy: v.spentBy, confirmed: v.confirmed } : {}),
            ...(v.status === "copyable" ? { sendOrder: v.trace.missing.map(tx => tx.txid), checked: v.trace.checked } : {}),
            ...(v.status === "blocked" ? { blocker: v.blocker, message: v.message } : {}),
            ...(v.status === "error" ? { message: v.message } : {}),
        })),
    };
    const write = (name: string, content: string) =>
        fs.writeFileSync(path.join(dir, name), content, { flag: "wx", mode: 0o600 });
    write("report.json", JSON.stringify(report, null, 2) + "\n");
    write("send-order.txids", order.map(tx => tx.txid).join("\n") + "\n");
    write("send-order.hex", order.map(tx => tx.rawHex).join("\n") + "\n");
    return dir;
}
