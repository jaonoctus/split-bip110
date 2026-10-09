import * as net from "net";
import * as tls from "tls";
import { crypto as bcrypto } from "bitcoinjs-lib";
import { BIP110, CHECK_HEIGHT, ChainProfile } from "./chain";

export const DEFAULT_ESPLORA = BIP110.defaultEsplora;

export type BackendUtxo = {
    txid: string;
    vout: number;
    value: number;
    // Unix time of the confirming block, when the backend reports it.
    blockTime?: number;
    confirmed: boolean;
};

// vin is the spending input's index in txid.
export type Outspend = { spent: boolean; txid?: string; vin?: number; confirmed?: boolean };

// Chain data source. Only individual addresses (or their
// script hashes) are ever sent; never the descriptor or xpub.
export interface Backend {
    readonly label: string;
    hasHistory(address: string, output: Buffer): Promise<boolean>;
    listUnspent(address: string, output: Buffer): Promise<BackendUtxo[]>;
    getRawTransaction(txid: string): Promise<string>;
    recommendedFeeRate(): Promise<number | undefined>;
    blockHash(height: number): Promise<string>;
    close(): void;
}

// The chains share history up to the split, so a block after it tells them apart.
export async function assertChain(backend: Backend, chain: ChainProfile): Promise<void> {
    const hash = await backend.blockHash(CHECK_HEIGHT);
    if (hash !== chain.checkHash) {
        throw new Error(`${backend.label} is not on the ${chain.name} chain (block ${CHECK_HEIGHT} is ${hash}, expected ${chain.checkHash})`);
    }
}

const TXID = /^[0-9a-f]{64}$/;
const MAX_SATS = 21000000 * 100000000;

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validUtxo(txid: unknown, vout: unknown, value: unknown): boolean {
    return typeof txid === "string" && TXID.test(txid) &&
        Number.isSafeInteger(vout) && (vout as number) >= 0 && (vout as number) <= 0xffffffff &&
        Number.isSafeInteger(value) && (value as number) > 0 && (value as number) <= MAX_SATS;
}

export class EsploraBackend implements Backend {
    readonly label: string;
    private readonly base: string;

    constructor(base = DEFAULT_ESPLORA, private readonly fetchImpl: typeof fetch = fetch) {
        this.base = base.replace(/\/$/, "");
        if (!/^https:\/\//.test(this.base) && !/^http:\/\/(localhost|127\.0\.0\.1)(:|\/)/.test(this.base)) {
            throw new Error("Esplora URL must use https (http is allowed only for localhost)");
        }
        this.label = this.base;
    }

    private async request(path: string): Promise<Response>;
    private async request(path: string, allowMissing: true): Promise<Response | null>;
    private async request(path: string, allowMissing = false): Promise<Response | null> {
        const url = `${this.base}${path}`;
        for (let attempt = 0; attempt < 5; attempt++) {
            let response: Response;
            try {
                response = await this.fetchImpl(url, { signal: AbortSignal.timeout(15000) });
            } catch (error) {
                if (attempt === 4) throw new Error(`Request failed: ${url}: ${error}`);
                await new Promise(resolve => setTimeout(resolve, 500 * 2 ** attempt));
                continue;
            }
            if (response.ok) return response;
            if (allowMissing && response.status === 404) return null;
            if (response.status !== 429 && response.status < 500) {
                throw new Error(`HTTP ${response.status} from ${url}`);
            }
            if (attempt === 4) throw new Error(`HTTP ${response.status} from ${url} after retries`);
            const retryAfter = Number(response.headers.get("retry-after"));
            const delay = Number.isFinite(retryAfter) && retryAfter > 0 ?
                Math.min(retryAfter * 1000, 15000) : 500 * 2 ** attempt;
            await new Promise(resolve => setTimeout(resolve, delay));
        }
        throw new Error(`Request failed: ${url}`);
    }

    private async json(path: string): Promise<unknown> {
        const response = await this.request(path);
        try { return await response.json(); }
        catch { throw new Error(`Invalid JSON from ${this.base}${path}`); }
    }

    async hasHistory(address: string): Promise<boolean> {
        const stats = await this.json(`/address/${encodeURIComponent(address)}`);
        if (!isRecord(stats) || !isRecord(stats.chain_stats) || !isRecord(stats.mempool_stats)) {
            throw new Error(`Invalid address response for ${address}`);
        }
        const chain = stats.chain_stats.tx_count;
        const mempool = stats.mempool_stats.tx_count;
        if (!Number.isSafeInteger(chain) || !Number.isSafeInteger(mempool)) {
            throw new Error(`Invalid address response for ${address}`);
        }
        return (chain as number) > 0 || (mempool as number) > 0;
    }

    async listUnspent(address: string): Promise<BackendUtxo[]> {
        const items = await this.json(`/address/${encodeURIComponent(address)}/utxo`);
        if (!Array.isArray(items)) throw new Error(`Invalid UTXO response for ${address}`);
        return items.map(item => {
            if (!isRecord(item) || !validUtxo(item.txid, item.vout, item.value) || !isRecord(item.status) ||
                typeof item.status.confirmed !== "boolean") {
                throw new Error(`Invalid UTXO response for ${address}`);
            }
            const blockTime = item.status.block_time;
            return {
                txid: item.txid as string,
                vout: item.vout as number,
                value: item.value as number,
                confirmed: item.status.confirmed,
                blockTime: Number.isSafeInteger(blockTime) ? blockTime as number : undefined,
            };
        });
    }

    async getRawTransaction(txid: string): Promise<string> {
        const hex = (await (await this.request(`/tx/${txid}/hex`)).text()).trim();
        if (!/^([0-9a-f]{2})+$/.test(hex)) throw new Error(`Invalid raw transaction for ${txid}`);
        return hex;
    }

    async blockHash(height: number): Promise<string> {
        return (await (await this.request(`/block-height/${height}`)).text()).trim();
    }

    // mempool's /tx/:txid/status answers 200 even for unknown txids, so ask for the transaction itself.
    async hasTransaction(txid: string): Promise<boolean> {
        const response = await this.request(`/tx/${txid}`, true);
        if (!response) return false;
        let tx: unknown;
        try { tx = await response.json(); } catch { throw new Error(`Invalid JSON from ${this.base}/tx/${txid}`); }
        if (!isRecord(tx) || tx.txid !== txid) throw new Error(`Invalid transaction response for ${txid}`);
        return true;
    }

    async outspend(txid: string, vout: number): Promise<Outspend> {
        const result = await this.json(`/tx/${txid}/outspend/${vout}`);
        if (!isRecord(result) || typeof result.spent !== "boolean" ||
            (result.spent && result.txid !== undefined && (typeof result.txid !== "string" || !TXID.test(result.txid))) ||
            (result.spent && result.vin !== undefined && (!Number.isSafeInteger(result.vin) || (result.vin as number) < 0)) ||
            (result.status !== undefined && (!isRecord(result.status) || typeof result.status.confirmed !== "boolean"))) {
            throw new Error(`Invalid outspend response for ${txid}:${vout}`);
        }
        return {
            spent: result.spent,
            txid: result.txid as string | undefined,
            vin: result.spent ? result.vin as number | undefined : undefined,
            confirmed: isRecord(result.status) ? result.status.confirmed as boolean : undefined,
        };
    }

    async recommendedFeeRate(): Promise<number | undefined> {
        try {
            const fees = await this.json("/v1/fees/recommended");
            if (isRecord(fees) && typeof fees.halfHourFee === "number" && fees.halfHourFee > 0) return fees.halfHourFee;
        } catch {
            // Not every Esplora server exposes mempool's fee endpoint.
        }
        return undefined;
    }

    close(): void {}
}

// Electrum protocol client (newline-delimited JSON-RPC over TCP or TLS).
export class ElectrumBackend implements Backend {
    readonly label: string;
    private nextId = 1;
    private buffer = "";
    private pending = new Map<number, { resolve(value: unknown): void; reject(error: Error): void }>();
    private closedError?: Error;

    private constructor(private readonly socket: net.Socket, label: string) {
        this.label = label;
        socket.setEncoding("utf8");
        socket.on("data", (chunk: string) => this.onData(chunk));
        const fail = (error: Error) => {
            this.closedError = error;
            for (const waiter of this.pending.values()) waiter.reject(error);
            this.pending.clear();
        };
        socket.on("error", fail);
        socket.on("close", () => fail(new Error(`Electrum connection to ${label} closed`)));
    }

    // Accepts "ssl://host:port", "tcp://host:port" or "host:port" (TLS).
    static async connect(url: string, options: { allowSelfSigned?: boolean } = {}): Promise<ElectrumBackend> {
        const match = /^(?:(ssl|tls|tcp):\/\/)?([^:/]+|\[[^\]]+\]):(\d{1,5})$/.exec(url.trim());
        if (!match) throw new Error("Electrum server must look like ssl://host:50002 or tcp://host:50001");
        const secure = match[1] !== "tcp";
        const host = match[2].replace(/^\[|\]$/g, "");
        const port = Number(match[3]);
        const socket = await new Promise<net.Socket>((resolve, reject) => {
            const connected = () => { s.setTimeout(0); resolve(s); };
            const s: net.Socket = secure ?
                tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: !options.allowSelfSigned }, connected) :
                net.connect({ host, port }, connected);
            s.setTimeout(20000, () => s.destroy(new Error(`Electrum server ${host}:${port} timed out`)));
            s.once("error", reject);
        });
        const client = new ElectrumBackend(socket, `${secure ? "ssl" : "tcp"}://${host}:${port}`);
        await client.call("server.version", ["split-bip110", "1.4"]);
        return client;
    }

    private onData(chunk: string): void {
        this.buffer += chunk;
        let newline: number;
        while ((newline = this.buffer.indexOf("\n")) >= 0) {
            const line = this.buffer.slice(0, newline).trim();
            this.buffer = this.buffer.slice(newline + 1);
            if (!line) continue;
            let message: unknown;
            try { message = JSON.parse(line); } catch { continue; }
            if (!isRecord(message) || typeof message.id !== "number") continue;
            const waiter = this.pending.get(message.id);
            if (!waiter) continue;
            this.pending.delete(message.id);
            if (message.error) {
                const error = isRecord(message.error) ? message.error.message : message.error;
                waiter.reject(new Error(`Electrum error: ${error}`));
            } else {
                waiter.resolve(message.result);
            }
        }
    }

    call(method: string, params: unknown[]): Promise<unknown> {
        if (this.closedError) return Promise.reject(this.closedError);
        const id = this.nextId++;
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(id);
                reject(new Error(`Electrum request ${method} timed out`));
            }, 30000);
            this.pending.set(id, {
                resolve: value => { clearTimeout(timer); resolve(value); },
                reject: error => { clearTimeout(timer); reject(error); },
            });
            this.socket.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
        });
    }

    private static scripthash(output: Buffer): string {
        return Buffer.from(bcrypto.sha256(output)).reverse().toString("hex");
    }

    async hasHistory(_address: string, output: Buffer): Promise<boolean> {
        const history = await this.call("blockchain.scripthash.get_history", [ElectrumBackend.scripthash(output)]);
        if (!Array.isArray(history)) throw new Error("Invalid Electrum history response");
        return history.length > 0;
    }

    async listUnspent(address: string, output: Buffer): Promise<BackendUtxo[]> {
        const items = await this.call("blockchain.scripthash.listunspent", [ElectrumBackend.scripthash(output)]);
        if (!Array.isArray(items)) throw new Error(`Invalid Electrum UTXO response for ${address}`);
        return items.map(item => {
            if (!isRecord(item) || !validUtxo(item.tx_hash, item.tx_pos, item.value) || !Number.isSafeInteger(item.height)) {
                throw new Error(`Invalid Electrum UTXO response for ${address}`);
            }
            return {
                txid: item.tx_hash as string,
                vout: item.tx_pos as number,
                value: item.value as number,
                confirmed: (item.height as number) > 0,
            };
        });
    }

    async getRawTransaction(txid: string): Promise<string> {
        const hex = await this.call("blockchain.transaction.get", [txid]);
        if (typeof hex !== "string" || !/^([0-9a-f]{2})+$/.test(hex)) throw new Error(`Invalid raw transaction for ${txid}`);
        return hex;
    }

    async blockHash(height: number): Promise<string> {
        const header = await this.call("blockchain.block.header", [height]);
        if (typeof header !== "string" || header.length !== 160) throw new Error(`Unexpected header at height ${height}`);
        return Buffer.from(bcrypto.hash256(Buffer.from(header, "hex"))).reverse().toString("hex");
    }

    async recommendedFeeRate(): Promise<number | undefined> {
        try {
            // BTC per kvB for confirmation within 3 blocks; -1 when unknown.
            const estimate = await this.call("blockchain.estimatefee", [3]);
            if (typeof estimate === "number" && estimate > 0) return Math.max(1, Math.round(estimate * 1e5 * 100) / 100);
        } catch {
            // Fall through to the caller's default.
        }
        return undefined;
    }

    close(): void {
        this.socket.end();
        this.socket.destroy();
    }
}
