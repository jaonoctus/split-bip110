import * as bip39 from "bip39";
import { BIP32Interface } from "bip32";
import { Transaction, crypto as bcrypto, networks } from "bitcoinjs-lib";
import { bip32 } from "../bip32";
import { signInputsUnified } from "../helper/unified-signer";
import { UTXO } from "../model/utxo";
import { Descriptor } from "./descriptor";
import { PlannedTx } from "./builder";

export function normalizeMnemonic(words: string): string {
    return words.trim().toLowerCase().replace(/\s+/g, " ");
}

export function mnemonicProblem(words: string): string | undefined {
    const normalized = normalizeMnemonic(words);
    if (bip39.validateMnemonic(normalized)) return undefined;
    const wordlist = bip39.wordlists.english;
    const invalid = normalized.split(" ").filter(w => !wordlist.includes(w));
    // Never echo the words themselves; only say how many are wrong.
    if (invalid.length > 0) return `${invalid.length} word(s) are not in the BIP39 English wordlist`;
    return "Checksum mismatch: a word is wrong or out of order";
}

export function rootFromMnemonic(words: string, passphrase: string): BIP32Interface {
    return bip32.fromSeed(bip39.mnemonicToSeedSync(normalizeMnemonic(words), passphrase), networks.bitcoin);
}

// Indexes of descriptor keys this root controls. Requires key origins in the descriptor.
export function matchKeys(descriptor: Descriptor, root: BIP32Interface): number[] {
    const matches: number[] = [];
    descriptor.keys.forEach((key, i) => {
        if (!key.hasOrigin || !root.fingerprint.equals(key.fingerprint)) return;
        const account = root.derivePath(key.originPath);
        if (account.publicKey.equals(key.xpub.publicKey) && account.chainCode.equals(key.xpub.chainCode)) {
            matches.push(i);
        }
    });
    return matches;
}

// Signs every planned transaction. "unified" uses SIGHASH_ALL|SIGHASH_UNIFIED (BIP110);
// "standard" signs as a normal BTC wallet would. `signers` maps descriptor key index to
// the root that owns it and must cover the threshold.
export function signPlan(
    descriptor: Descriptor, plan: PlannedTx[], signers: Map<number, BIP32Interface>, sighash: "unified" | "standard" = "unified",
): Transaction[] {
    const keyIndexes = [...signers.keys()].sort((a, b) => a - b).slice(0, descriptor.threshold);
    if (keyIndexes.length < descriptor.threshold) {
        throw new Error(`Need ${descriptor.threshold} signing key(s), have ${keyIndexes.length}`);
    }
    if (sighash === "standard") return plan.map(tx => signStandard(descriptor, tx, signers, keyIndexes));
    return plan.map(tx => {
        const utxos: UTXO[] = [];
        const privkeys = new Map<UTXO, Buffer[]>();
        for (const coin of tx.coins) {
            const derived = descriptor.derive(coin.branch, coin.index);
            const pairs = keyIndexes.map(k => {
                const node = signers.get(k)!.derivePath(derived.keys[k].path);
                if (!node.publicKey.equals(derived.keys[k].pubkey)) throw new Error(`Derived key mismatch for ${coin.address}`);
                return { pubkey: node.publicKey, privkey: node.privateKey! };
            });
            // CHECKMULTISIG needs signatures in the same order as the sorted pubkeys.
            pairs.sort((a, b) => a.pubkey.compare(b.pubkey));
            const utxo = new UTXO(coin.txid, coin.vout, coin.value, coin.address);
            if (derived.witnessScript) {
                utxo.threshold = descriptor.threshold;
                utxo.witnessScript = derived.witnessScript;
            }
            utxos.push(utxo);
            privkeys.set(utxo, pairs.map(p => p.privkey));
        }
        signInputsUnified(tx.psbt, utxos, privkeys);
        return tx.psbt.extractTransaction();
    });
}

function signStandard(descriptor: Descriptor, tx: PlannedTx, signers: Map<number, BIP32Interface>, keyIndexes: number[]): Transaction {
    tx.coins.forEach((coin, input) => {
        const derived = descriptor.derive(coin.branch, coin.index);
        for (const k of keyIndexes) {
            const node = signers.get(k)!.derivePath(derived.keys[k].path);
            if (!node.publicKey.equals(derived.keys[k].pubkey)) throw new Error(`Derived key mismatch for ${coin.address}`);
            // Key-path taproot spends sign with the key tweaked by the (script-less) taproot commitment.
            const signer = descriptor.kind === "tr" ? node.tweak(bcrypto.taggedHash("TapTweak", node.publicKey.subarray(1))) : node;
            tx.psbt.signInput(input, signer);
        }
    });
    tx.psbt.finalizeAllInputs();
    return tx.psbt.extractTransaction();
}
