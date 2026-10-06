import * as bip39 from "bip39";
import { BIP32Interface } from "bip32";
import { ECPairFactory, ECPairInterface } from "ecpair";
import * as ecc from "tiny-secp256k1";
import { Transaction, crypto as bcrypto, networks } from "bitcoinjs-lib";
import { bip32 } from "../bip32";
import { signInputsUnified } from "../helper/unified-signer";
import { UTXO } from "../model/utxo";
import { DerivedKey, DerivedOutput, Descriptor, accountPath } from "./descriptor";
import { PlannedTx } from "./builder";
import { Coin } from "./scan";

const ECPair = ECPairFactory(ecc);

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

export type SigningKey = BIP32Interface | ECPairInterface;

// Gives the private key for descriptor key `keyIndex` at a derived position, or undefined when
// this source does not control it.
export type KeySigner = (keyIndex: number, derived: DerivedKey) => SigningKey | undefined;

function sameXpub(a: BIP32Interface, b: BIP32Interface): boolean {
    return a.publicKey.equals(b.publicKey) && a.chainCode.equals(b.chainCode);
}

// Indexes of descriptor keys this root controls. Needs key origins in the descriptor, or a
// single-sig account xpub at its type's standard path.
export function matchKeys(descriptor: Descriptor, root: BIP32Interface): number[] {
    const matches: number[] = [];
    descriptor.keys.forEach((key, i) => {
        const path = accountPath(descriptor, key);
        if (path === undefined || (key.hasOrigin && !root.fingerprint.equals(key.fingerprint))) return;
        const node = root.derivePath(path);
        if (key.xpub ? sameXpub(node, key.xpub) : node.publicKey.equals(key.pubkey)) matches.push(i);
    });
    return matches;
}

function checked(key: SigningKey, derived: DerivedKey): SigningKey {
    if (!key.publicKey.equals(derived.pubkey)) throw new Error("Derived key mismatch");
    return key;
}

// Derives below `node`, which sits at the descriptor key itself (its xpub, or the single key).
function belowKey(node: BIP32Interface, derived: DerivedKey): BIP32Interface {
    const relative = derived.path.slice(derived.key.originPath.length + 1);
    return relative ? node.derivePath(relative) : node;
}

// Signs with a seed or master xprv for the descriptor keys it controls (see matchKeys).
export function rootSigner(descriptor: Descriptor, root: BIP32Interface, keyIndexes = matchKeys(descriptor, root)): KeySigner {
    return (k, derived) => {
        if (!keyIndexes.includes(k)) return undefined;
        return checked(belowKey(root.derivePath(accountPath(descriptor, derived.key)!), derived), derived);
    };
}

// Signs with an account-level xprv for the descriptor keys whose xpub it is.
export function xprvSigner(descriptor: Descriptor, node: BIP32Interface): KeySigner {
    if (node.depth === 0) return rootSigner(descriptor, node);
    return (k, derived) => {
        const xpub = descriptor.keys[k].xpub;
        if (!xpub || !sameXpub(node.neutered(), xpub)) return undefined;
        return checked(belowKey(node, derived), derived);
    };
}

// Signs with individual private keys, matched by public key against each derived key.
export function wifSigner(pairs: ECPairInterface[]): KeySigner {
    const byPubkey = new Map(pairs.map(pair => [pair.publicKey.toString("hex"), pair]));
    return (_k, derived) => byPubkey.get(derived.pubkey.toString("hex"));
}

// Signs with the xprvs and WIFs that were part of the descriptor itself, if any.
export function descriptorSigner(descriptor: Descriptor): KeySigner | undefined {
    if (!descriptor.keys.some(key => key.secret)) return undefined;
    return (k, derived) => {
        const secret = descriptor.keys[k].secret;
        if (!secret) return undefined;
        return checked("derivePath" in secret ? belowKey(secret, derived) : secret, derived);
    };
}

export function parseWifs(text: string): ECPairInterface[] {
    const pairs = text.split(/[\s,]+/).filter(Boolean).map(wif => {
        let pair: ECPairInterface;
        try { pair = ECPair.fromWIF(wif, networks.bitcoin); }
        catch { throw new Error("Not a valid mainnet WIF private key"); }
        if (!pair.compressed) throw new Error("Uncompressed private keys are not supported");
        return pair;
    });
    if (pairs.length === 0) throw new Error("Paste at least one WIF private key");
    return pairs;
}

// Private keys for one input: the first `threshold` descriptor keys some signer covers,
// or undefined when the signers do not cover enough of them.
function inputKeys(descriptor: Descriptor, derived: DerivedOutput, signers: KeySigner[]): SigningKey[] | undefined {
    const keys: SigningKey[] = [];
    for (let k = 0; k < descriptor.keys.length && keys.length < descriptor.threshold; k++) {
        for (const signer of signers) {
            const key = signer(k, derived.keys[k]);
            if (key) { keys.push(key); break; }
        }
    }
    return keys.length === descriptor.threshold ? keys : undefined;
}

// Coins of the plan the signers cannot fully sign yet.
export function unsignedCoins(descriptor: Descriptor, plan: PlannedTx[], signers: KeySigner[]): Coin[] {
    return plan.flatMap(tx => tx.coins).filter(coin => !inputKeys(descriptor, descriptor.derive(coin.branch, coin.index), signers));
}

function toSigners(descriptor: Descriptor, signers: KeySigner[] | Map<number, BIP32Interface>): KeySigner[] {
    if (Array.isArray(signers)) return signers;
    return [...signers].map(([k, root]) => rootSigner(descriptor, root, [k]));
}

function keysFor(descriptor: Descriptor, signers: KeySigner[], coin: Coin): { derived: DerivedOutput; keys: SigningKey[] } {
    const derived = descriptor.derive(coin.branch, coin.index);
    const keys = inputKeys(descriptor, derived, signers);
    if (!keys) throw new Error(`Need ${descriptor.threshold} signing key(s) for ${coin.address}`);
    return { derived, keys };
}

// Signs every planned transaction. "unified" uses SIGHASH_ALL|SIGHASH_UNIFIED (BIP110);
// "standard" signs as a normal BTC wallet would. `signers` are the key sources (or a map of
// descriptor key index to the seed root that owns it) and must cover the threshold of every input.
export function signPlan(
    descriptor: Descriptor, plan: PlannedTx[], signerList: KeySigner[] | Map<number, BIP32Interface>, sighash: "unified" | "standard" = "unified",
): Transaction[] {
    const signers = toSigners(descriptor, signerList);
    if (sighash === "standard") return plan.map(tx => signStandard(descriptor, tx, signers));
    return plan.map(tx => {
        const utxos: UTXO[] = [];
        const privkeys = new Map<UTXO, Buffer[]>();
        for (const coin of tx.coins) {
            const { derived, keys } = keysFor(descriptor, signers, coin);
            const pairs = keys.map(key => ({ pubkey: key.publicKey, privkey: key.privateKey! }));
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

function signStandard(descriptor: Descriptor, tx: PlannedTx, signers: KeySigner[]): Transaction {
    tx.coins.forEach((coin, input) => {
        for (const key of keysFor(descriptor, signers, coin).keys) {
            // Key-path taproot spends sign with the key tweaked by the (script-less) taproot commitment.
            const signer = descriptor.kind === "tr" ? key.tweak(bcrypto.taggedHash("TapTweak", key.publicKey.subarray(1))) : key;
            tx.psbt.signInput(input, signer);
        }
    });
    tx.psbt.finalizeAllInputs();
    return tx.psbt.extractTransaction();
}
