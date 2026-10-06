import { BIP32Interface } from "bip32";
import { Psbt, Transaction, address as btcAddress, networks } from "bitcoinjs-lib";
import { SIGHASH_ALL, SIGHASH_UNIFIED } from "../helper/unified-sighash";
import { ScriptType, ScriptTypeEnum } from "../script-type";
import { Descriptor } from "./descriptor";
import { Coin, formatBtc, outpoint } from "./scan";

export const UNIFIED_HASH_TYPE = SIGHASH_ALL | SIGHASH_UNIFIED;
const RBF_SEQUENCE = 0xfffffffd;

export type Destination =
    | { kind: "address"; address: string }
    // `account` is the account-level xpub; receive addresses are account/0/i.
    | { kind: "xpub"; account: BIP32Interface; scriptType: ScriptType; startIndex: number }
    // Receive addresses are the descriptor's first branch at startIndex, startIndex + 1, ...
    | { kind: "descriptor"; descriptor: Descriptor; startIndex: number };

export type PlannedTx = {
    psbt: Psbt;
    coins: Coin[];
    address: string;
    addressIndex?: number;
    inputValue: number;
    outputValue: number;
    fee: number;
    vsize: number;
};

export type GroupingMode = "separate" | "consolidate";

// "separate": one transaction per coin, except coins sharing an address (already linked on BTC).
export function groupCoins(coins: Coin[], mode: GroupingMode): Coin[][] {
    if (mode === "consolidate") return coins.length > 0 ? [coins] : [];
    const byAddress = new Map<string, Coin[]>();
    for (const coin of coins) {
        const group = byAddress.get(coin.address);
        if (group) group.push(coin); else byAddress.set(coin.address, [coin]);
    }
    return [...byAddress.values()];
}

export function destinationAddress(destination: Destination, offset: number): { address: string; index?: number } {
    if (destination.kind === "address") return { address: destination.address };
    const index = destination.startIndex + offset;
    if (destination.kind === "descriptor") return { address: destination.descriptor.derive(0, index).address, index };
    const pubkey = destination.account.derive(0).derive(index).publicKey;
    return { address: destination.scriptType.toPayment(undefined, pubkey, networks.bitcoin).address!, index };
}

function varIntSize(n: number): number {
    return n < 0xfd ? 1 : n <= 0xffff ? 3 : 5;
}

// Upper-bound input weight, assuming 72-byte DER signatures (73 with the hash type byte).
// Taproot assumes the explicit hash type byte too, which overestimates SIGHASH_DEFAULT by 1 weight unit.
function inputWeight(descriptor: Descriptor): { weight: number; witness: boolean } {
    const outpointAndSequence = 32 + 4 + 4;
    switch (descriptor.kind) {
        case "pkh":
            return { weight: (outpointAndSequence + 1 + 1 + 73 + 1 + 33) * 4, witness: false };
        case "sh-wpkh":
            return { weight: (outpointAndSequence + 1 + 23) * 4 + 1 + 1 + 73 + 1 + 33, witness: true };
        case "wpkh":
            return { weight: (outpointAndSequence + 1) * 4 + 1 + 1 + 73 + 1 + 33, witness: true };
        case "tr":
            // Schnorr signature plus the explicit (non-default) hash type byte.
            return { weight: (outpointAndSequence + 1) * 4 + 1 + 1 + 65, witness: true };
        case "wsh-sortedmulti": {
            const scriptSize = 3 + 34 * descriptor.keys.length;
            const items = 2 + descriptor.threshold;
            const witness = varIntSize(items) + 1 + descriptor.threshold * (1 + 73) + varIntSize(scriptSize) + scriptSize;
            return { weight: (outpointAndSequence + 1) * 4 + witness, witness: true };
        }
    }
}

export function estimateVsize(descriptor: Descriptor, inputs: number, outputScript: Buffer): number {
    const input = inputWeight(descriptor);
    const base = 4 + varIntSize(inputs) + varIntSize(1) + 8 + varIntSize(outputScript.length) + outputScript.length + 4;
    const weight = base * 4 + (input.witness ? 2 : 0) + inputs * input.weight;
    return Math.ceil(weight / 4);
}

// Legacy inputs do not commit to the spent value, so check the raw parent transaction.
export function verifyParent(coin: Coin, rawHex: string, expectedScript: Buffer): Buffer {
    const raw = Buffer.from(rawHex, "hex");
    const tx = Transaction.fromBuffer(raw);
    if (tx.getId() !== coin.txid) throw new Error(`Server returned the wrong transaction for ${coin.txid}`);
    const out = tx.outs[coin.vout];
    if (!out || out.value !== coin.value || !out.script.equals(expectedScript)) {
        throw new Error(`Server data for ${outpoint(coin)} does not match its parent transaction`);
    }
    return raw;
}

// `sighash` "unified" requests SIGHASH_ALL|SIGHASH_UNIFIED (BIP110); "standard" leaves the
// default (SIGHASH_ALL, or SIGHASH_DEFAULT for taproot) so any BTC wallet can sign.
export function buildPlan(
    descriptor: Descriptor, groups: Coin[][], destination: Destination, feeRate: number, parents: Map<string, Buffer>,
    sighash: "unified" | "standard" = "unified",
): PlannedTx[] {
    if (!(feeRate > 0)) throw new Error("Fee rate must be positive");
    return groups.map((coins, offset) => {
        const { address, index } = destinationAddress(destination, offset);
        const outputScript = btcAddress.toOutputScript(address, networks.bitcoin);
        const inputValue = coins.reduce((sum, coin) => sum + coin.value, 0);
        const vsize = estimateVsize(descriptor, coins.length, outputScript);
        const fee = Math.ceil(vsize * feeRate);
        const outputValue = inputValue - fee;
        const dust = ScriptType.fromAddress(address, networks.bitcoin).dustAmount;
        if (outputValue < dust) {
            throw new Error(`Coins ${coins.map(outpoint).join(", ")} leave ${outputValue} sats after a ${fee} sat fee, ` +
                `below the ${dust} sat dust limit. Deselect them, consolidate, or lower the fee rate.`);
        }

        const psbt = new Psbt({ network: networks.bitcoin });
        for (const coin of coins) {
            const derived = descriptor.derive(coin.branch, coin.index);
            if (derived.address !== coin.address) throw new Error(`Coin ${outpoint(coin)} does not belong to this descriptor`);
            const input: Parameters<Psbt["addInput"]>[0] = {
                hash: coin.txid,
                index: coin.vout,
                sequence: RBF_SEQUENCE,
            };
            if (sighash === "unified") input.sighashType = UNIFIED_HASH_TYPE;
            if (descriptor.scriptType.typeEnum === ScriptTypeEnum.P2PKH) {
                const parent = parents.get(coin.txid);
                if (!parent) throw new Error(`Missing parent transaction for legacy coin ${outpoint(coin)}`);
                input.nonWitnessUtxo = parent;
            } else {
                input.witnessUtxo = { script: derived.output, value: coin.value };
            }
            if (derived.redeemScript) input.redeemScript = derived.redeemScript;
            if (derived.witnessScript) input.witnessScript = derived.witnessScript;
            if (descriptor.kind === "tr") {
                const xonly = derived.keys[0].pubkey.subarray(1);
                input.tapInternalKey = xonly;
                input.tapBip32Derivation = [{
                    masterFingerprint: derived.keys[0].key.fingerprint,
                    path: derived.keys[0].path,
                    pubkey: xonly,
                    leafHashes: [],
                }];
            } else {
                input.bip32Derivation = derived.keys.map(k => ({
                    masterFingerprint: k.key.fingerprint,
                    path: k.path,
                    pubkey: k.pubkey,
                }));
            }
            psbt.addInput(input);
        }
        psbt.addOutput({ address, value: outputValue });
        return { psbt, coins, address, addressIndex: index, inputValue, outputValue, fee, vsize };
    });
}

// Coins that the plan would tie together on the BIP110 chain although they sat on
// different addresses (and so were not necessarily linked on BTC).
export function linkageWarnings(plan: PlannedTx[], destination: Destination): string[] {
    const warnings: string[] = [];
    for (const [i, tx] of plan.entries()) {
        const addresses = new Set(tx.coins.map(c => c.address));
        if (addresses.size > 1) {
            warnings.push(`Transaction ${i + 1} spends coins from ${addresses.size} different addresses together, ` +
                "publicly linking them as one owner.");
        }
    }
    if (destination.kind === "address" && plan.length > 1) {
        warnings.push(`All ${plan.length} transactions pay the same address, which links every selected coin ` +
            "to one owner.");
    }
    return warnings;
}

export function describePlan(plan: PlannedTx[], feeRate: number): string {
    const lines: string[] = [];
    for (const [i, tx] of plan.entries()) {
        lines.push(`=== Transaction ${i + 1} of ${plan.length}`);
        lines.push(tx.coins.length === 1 ? "Coin:" : "Coins:");
        for (const coin of tx.coins) {
            lines.push(`  ${outpoint(coin)}  ${coin.address}  ${formatBtc(coin.value)} BTC`);
        }
        lines.push("To:");
        lines.push(`  ${tx.address}${tx.addressIndex !== undefined ? ` (address #${tx.addressIndex})` : ""}`);
        lines.push(`  Value: ${formatBtc(tx.outputValue)} BTC`);
        lines.push("Fee:");
        lines.push(`  Estimated size: ${tx.vsize} vb`);
        lines.push(`  Fee: ${tx.fee} sats (${feeRate} sat/vb target)`);
        lines.push(`  Fee %: ${((tx.fee / tx.inputValue) * 100).toFixed(2)}%`);
        lines.push("===", "");
    }
    const totalIn = plan.reduce((s, t) => s + t.inputValue, 0);
    const totalFee = plan.reduce((s, t) => s + t.fee, 0);
    lines.push(`Total: ${plan.length} transaction(s), ${formatBtc(totalIn)} BTC in, ${formatBtc(totalIn - totalFee)} BTC out, ${totalFee} sats fees`);
    return lines.join("\n");
}
