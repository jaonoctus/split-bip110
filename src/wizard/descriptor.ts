import { createHash } from "crypto";
import base58 from "bs58check";
import { BIP32Interface } from "bip32";
import { ECPairFactory, ECPairInterface } from "ecpair";
import * as ecc from "tiny-secp256k1";
import { crypto as bcrypto, networks, payments } from "bitcoinjs-lib";
import { bip32 } from "../bip32";
import { ScriptType } from "../script-type";

const ECPair = ECPairFactory(ecc);

// BIP 380 descriptor checksum character sets and generator constants.
const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

function polymod(symbols: number[]): bigint {
    let check = 1n;
    for (const symbol of symbols) {
        const top = check >> 35n;
        check = ((check & 0x7ffffffffn) << 5n) ^ BigInt(symbol);
        for (let i = 0; i < 5; i++) {
            if ((top >> BigInt(i)) & 1n) check ^= GENERATORS[i];
        }
    }
    return check;
}

export function descriptorChecksum(body: string): string {
    const symbols: number[] = [];
    const groups: number[] = [];
    for (const character of body) {
        const value = INPUT_CHARSET.indexOf(character);
        if (value < 0) throw new Error("Descriptor contains a character outside the BIP 380 checksum alphabet");
        symbols.push(value & 31);
        groups.push(value >> 5);
        if (groups.length === 3) {
            symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
            groups.length = 0;
        }
    }
    if (groups.length === 1) symbols.push(groups[0]);
    if (groups.length === 2) symbols.push(groups[0] * 3 + groups[1]);
    const checksum = polymod([...symbols, 0, 0, 0, 0, 0, 0, 0, 0]) ^ 1n;
    let result = "";
    for (let i = 0; i < 8; i++) {
        result += CHECKSUM_CHARSET[Number((checksum >> BigInt(5 * (7 - i))) & 31n)];
    }
    return result;
}

export type DescriptorKind = "pkh" | "sh-wpkh" | "wpkh" | "tr" | "wsh-sortedmulti";

export type DescriptorKey = {
    // Master fingerprint from the key origin, or the key's own fingerprint when there is no origin.
    fingerprint: Buffer;
    hasOrigin: boolean;
    // Path from the master key to the key, e.g. "m/84'/0'/0'" ("m" without origin).
    originPath: string;
    // Extended public key of a ranged key; undefined for a single key (WIF or hex pubkey).
    xpub?: BIP32Interface;
    // Public key of the key itself (the xpub's key for a ranged key).
    pubkey: Buffer;
    // Private key when the descriptor held an xprv or WIF. Kept in memory only: `expression`
    // and the descriptor text only ever hold the public form.
    secret?: BIP32Interface | ECPairInterface;
    // Public form of the key expression.
    expression: string;
    steps: Array<number | number[]>;
    branches: number;
};

export type DerivedKey = {
    key: DescriptorKey;
    pubkey: Buffer;
    // Full path from the master key, e.g. "m/84'/0'/0'/0/5".
    path: string;
};

export type DerivedOutput = {
    address: string;
    output: Buffer;
    redeemScript?: Buffer;
    witnessScript?: Buffer;
    // In descriptor key order.
    keys: DerivedKey[];
};

export type Descriptor = {
    // Descriptor as given by the user, with private keys replaced by public ones, with checksum.
    text: string;
    // Stable identifier: sha256 of the body with hardened markers normalized to "h".
    id: string;
    kind: DescriptorKind;
    scriptType: ScriptType;
    // Signatures required; 1 for single-sig.
    threshold: number;
    keys: DescriptorKey[];
    branches: number;
    // False when every key is a single key: then only index 0 of branch 0 exists.
    ranged: boolean;
    // True when a receive-only "/0/*" descriptor was widened to also scan "/1/*" change.
    addedChange: boolean;
    branchStep(branch: number): string;
    derive(branch: number, index: number): DerivedOutput;
};

function pathIndex(text: string): number {
    if (!/^(0|[1-9]\d*)$/.test(text)) throw new Error(`Unsupported descriptor path step: ${text}`);
    const value = Number(text);
    if (!Number.isSafeInteger(value) || value >= 0x80000000) {
        throw new Error(`Descriptor path index out of range: ${text}`);
    }
    return value;
}

const BASE58 = "[1-9A-HJ-NP-Za-km-z]";
const EXTENDED_KEY = new RegExp(`^[xyz](?:pub|prv)${BASE58}+$`);
const WIF = new RegExp(`^[5KL]${BASE58}{50,51}$`);
const HEX_PUBKEY = /^(?:0[23][0-9a-fA-F]{64}|04[0-9a-fA-F]{128})$/;

// True for key material that must not be shown or stored: an xprv/yprv/zprv or a WIF.
export function isPrivateKey(text: string): boolean {
    return /^[xyz]prv/.test(text) || WIF.test(text);
}

function parseOrigin(origin: string | undefined): { fingerprint?: Buffer; originPath: string } {
    if (!origin) return { originPath: "m" };
    const originMatch = /^([0-9a-fA-F]{8})((?:\/(?:0|[1-9]\d*)(?:h|H|')?)*)$/.exec(origin);
    if (!originMatch) throw new Error("Invalid descriptor key origin");
    return { fingerprint: Buffer.from(originMatch[1], "hex"), originPath: "m" + originMatch[2].replace(/[hH]/g, "'") };
}

// A single key: a WIF private key or a hex public key. Only compressed keys are supported.
function parseSingleKey(origin: string | undefined, encoded: string): DescriptorKey {
    const { fingerprint, originPath } = parseOrigin(origin);
    let pubkey: Buffer;
    let secret: ECPairInterface | undefined;
    if (WIF.test(encoded)) {
        try { secret = ECPair.fromWIF(encoded, networks.bitcoin); }
        catch { throw new Error("Invalid mainnet WIF private key"); }
        if (!secret.compressed) throw new Error("Uncompressed private keys are not supported");
        pubkey = secret.publicKey;
    } else {
        if (encoded.startsWith("04")) throw new Error("Uncompressed public keys are not supported");
        pubkey = Buffer.from(encoded, "hex");
        if (!ecc.isPoint(pubkey)) throw new Error("Invalid public key in descriptor");
    }
    return {
        fingerprint: fingerprint ?? bcrypto.hash160(pubkey).subarray(0, 4),
        hasOrigin: !!origin,
        originPath,
        pubkey,
        secret,
        expression: `${origin ? `[${origin}]` : ""}${pubkey.toString("hex")}`,
        steps: [],
        branches: 1,
    };
}

function parseKey(expression: string): DescriptorKey {
    const match = /^(?:\[([^\]]+)\])?([0-9a-zA-Z]+)(.*)$/.exec(expression);
    if (!match) throw new Error("Descriptor key must be a mainnet xpub, xprv, WIF or hex public key, optionally with key origin");
    const [, origin, encoded, suffix] = match;
    if (!EXTENDED_KEY.test(encoded)) {
        if (suffix !== "" || !(WIF.test(encoded) || HEX_PUBKEY.test(encoded))) {
            throw new Error("Descriptor key must be a mainnet xpub, xprv, WIF or hex public key, optionally with key origin");
        }
        return parseSingleKey(origin, encoded);
    }
    if (!/^x(pub|prv)/.test(encoded)) throw new Error("Descriptor keys must be xpubs or xprvs (convert ypub/zpub to xpub)");
    const { fingerprint, originPath } = parseOrigin(origin);
    let node: BIP32Interface;
    try { node = bip32.fromBase58(encoded, networks.bitcoin); }
    catch { throw new Error("Invalid mainnet extended key in descriptor"); }
    if (encoded.startsWith("xpub") !== node.isNeutered()) throw new Error("Invalid mainnet extended key in descriptor");
    const xpub = node.neutered();
    if (!suffix.startsWith("/")) throw new Error("Descriptor xpub must end in a ranged /* path");
    const parts = suffix.slice(1).split("/");
    if (parts.pop() !== "*") throw new Error("Descriptor xpub must end in a ranged /* path");
    const steps: Array<number | number[]> = [];
    let branches = 1;
    for (const part of parts) {
        if (part.startsWith("<") && part.endsWith(">")) {
            if (branches !== 1) throw new Error("Only one multipath step is supported per key");
            const choices = part.slice(1, -1).split(";").map(pathIndex);
            if (choices.length < 2 || new Set(choices).size !== choices.length) {
                throw new Error("Descriptor multipath step needs distinct alternatives");
            }
            branches = choices.length;
            steps.push(choices);
        } else {
            steps.push(pathIndex(part));
        }
    }
    return {
        fingerprint: fingerprint ?? xpub.fingerprint,
        hasOrigin: !!origin,
        originPath,
        xpub,
        pubkey: xpub.publicKey,
        secret: node.isNeutered() ? undefined : node,
        expression: `${origin ? `[${origin}]` : ""}${xpub.toBase58()}${suffix}`,
        steps,
        branches,
    };
}

function stepsForBranch(key: DescriptorKey, branch: number): number[] {
    return key.steps.map(step => Array.isArray(step) ? step[key.branches === 1 ? 0 : branch] : step);
}

// Receive-only descriptors ending in ".../0/*" are widened to "<0;1>" so change is scanned too.
function addChangeBranch(keys: DescriptorKey[]): boolean {
    const eligible = keys.every(key => key.branches === 1 && key.steps.length > 0 && key.steps[key.steps.length - 1] === 0);
    if (!eligible) return false;
    for (const key of keys) {
        key.steps[key.steps.length - 1] = [0, 1];
        key.branches = 2;
    }
    return true;
}

export function parseDescriptor(input: string): Descriptor {
    const text = input.trim().replace(/\s+/g, "");
    const hash = text.indexOf("#");
    const body = hash < 0 ? text : text.slice(0, hash);
    const checksum = descriptorChecksum(body);
    if (hash >= 0 && text.slice(hash + 1) !== checksum) {
        throw new Error("Invalid descriptor checksum");
    }

    let kind: DescriptorKind;
    let threshold = 1;
    let keyExpressions: string[];
    const multisig = /^wsh\(sortedmulti\((\d+),(.+)\)\)$/.exec(body);
    if (multisig) {
        kind = "wsh-sortedmulti";
        threshold = Number(multisig[1]);
        keyExpressions = multisig[2].split(",");
        if (keyExpressions.length < 1 || keyExpressions.length > 16 ||
            !Number.isSafeInteger(threshold) || threshold < 1 || threshold > keyExpressions.length) {
            throw new Error("Invalid sortedmulti threshold or key count (maximum 16 keys)");
        }
    } else {
        const single = /^(tr|wpkh|pkh)\(([^()]+)\)$/.exec(body);
        const nested = /^sh\(wpkh\(([^()]+)\)\)$/.exec(body);
        if (single) {
            kind = single[1] as DescriptorKind;
            keyExpressions = [single[2]];
        } else if (nested) {
            kind = "sh-wpkh";
            keyExpressions = [nested[1]];
        } else {
            throw new Error("Supported descriptors: tr(KEY), wpkh(KEY), pkh(KEY), sh(wpkh(KEY)), wsh(sortedmulti(...))");
        }
    }

    const keys = keyExpressions.map(parseKey);
    // Rebuilt from the public key expressions, so private keys never reach the text or the id.
    const expressions = keys.map(key => key.expression).join(",");
    const publicBody = kind === "wsh-sortedmulti" ? `wsh(sortedmulti(${threshold},${expressions}))` :
        kind === "sh-wpkh" ? `sh(wpkh(${expressions}))` : `${kind}(${expressions})`;
    const publicChecksum = descriptorChecksum(publicBody);
    const ranged = keys.some(key => key.xpub);
    const addedChange = addChangeBranch(keys);
    const branches = Math.max(...keys.map(key => key.branches));
    if (keys.some(key => key.branches !== 1 && key.branches !== branches)) {
        throw new Error("Descriptor multipath keys must have the same number of alternatives");
    }

    const scriptType = kind === "pkh" ? ScriptType.P2PKH :
        kind === "sh-wpkh" ? ScriptType.P2SH :
        kind === "wpkh" ? ScriptType.P2WPKH :
        kind === "tr" ? ScriptType.P2TR : ScriptType.P2WSH;

    const branchNodes = keys.map(() => new Map<number, BIP32Interface>());
    function childKey(keyIndex: number, branch: number, index: number): Buffer {
        const key = keys[keyIndex];
        return key.xpub ? branchNode(keyIndex, branch).derive(index).publicKey : key.pubkey;
    }
    function branchNode(keyIndex: number, branch: number): BIP32Interface {
        let node = branchNodes[keyIndex].get(branch);
        if (!node) {
            node = keys[keyIndex].xpub!;
            for (const step of stepsForBranch(keys[keyIndex], branch)) node = node.derive(step);
            branchNodes[keyIndex].set(branch, node);
        }
        return node;
    }

    const network = networks.bitcoin;
    const id = createHash("sha256").update(publicBody.replace(/['H]/g, "h")).digest("hex").slice(0, 16);

    return {
        text: `${publicBody}#${publicChecksum}`,
        id,
        kind,
        scriptType,
        threshold,
        keys,
        branches,
        ranged,
        addedChange,
        branchStep(branch) {
            const step = keys[0].steps.find(s => Array.isArray(s));
            return Array.isArray(step) ? String(step[branch]) : String(branch);
        },
        derive(branch, index) {
            if (!Number.isSafeInteger(branch) || branch < 0 || branch >= branches ||
                !Number.isSafeInteger(index) || index < 0 || index >= 0x80000000 || (!ranged && index !== 0)) {
                throw new Error("Descriptor branch or index out of range");
            }
            const derived: DerivedKey[] = keys.map((key, keyIndex) => ({
                key,
                pubkey: childKey(keyIndex, branch, index),
                path: key.xpub ? [key.originPath, ...stepsForBranch(key, branch), index].join("/") : key.originPath,
            }));
            const pubkey = derived[0].pubkey;
            switch (kind) {
                case "pkh": {
                    const p = payments.p2pkh({ pubkey, network });
                    return { address: p.address!, output: p.output!, keys: derived };
                }
                case "wpkh": {
                    const p = payments.p2wpkh({ pubkey, network });
                    return { address: p.address!, output: p.output!, keys: derived };
                }
                case "sh-wpkh": {
                    const redeem = payments.p2wpkh({ pubkey, network });
                    const p = payments.p2sh({ redeem, network });
                    return { address: p.address!, output: p.output!, redeemScript: redeem.output!, keys: derived };
                }
                case "tr": {
                    const p = payments.p2tr({ internalPubkey: pubkey.subarray(1), network });
                    return { address: p.address!, output: p.output!, keys: derived };
                }
                case "wsh-sortedmulti": {
                    const sorted = derived.map(d => d.pubkey).sort(Buffer.compare);
                    const redeem = payments.p2ms({ m: threshold, pubkeys: sorted, network });
                    const p = payments.p2wsh({ redeem, network });
                    return { address: p.address!, output: p.output!, witnessScript: redeem.output!, keys: derived };
                }
            }
        },
    };
}

export function walletFingerprints(descriptor: Descriptor): string {
    return descriptor.keys.map(key => key.fingerprint.toString("hex")).join("-");
}

// Converts a ypub/zpub (yprv/zprv) to the same key with xpub (xprv) version bytes.
export function toXpub(value: string): string {
    if (value.startsWith("xp")) return value;
    const data = Buffer.from(base58.decode(value));
    data.writeUInt32BE(value.slice(1, 4) === "prv" ? networks.bitcoin.bip32.private : networks.bitcoin.bip32.public, 0);
    return base58.encode(data);
}

const STANDARD_PURPOSE: Partial<Record<DescriptorKind, number>> = { "pkh": 44, "sh-wpkh": 49, "wpkh": 84, "tr": 86 };

// A bare key (optionally with key origin) has no script type of its own: a ypub/zpub names its
// type, while an xpub, a WIF or a hex public key could be any of the common single-sig types.
// Private keys work the same as their public counterparts. Returns one descriptor per possible
// type, or undefined when the input is not a bare key.
export function keyCandidates(input: string): Descriptor[] | undefined {
    const match = /^(\[[^\]]+\])?([0-9a-zA-Z]+)$/.exec(input.trim());
    if (!match) return undefined;
    const [, origin = "", encoded] = match;
    let key: string;
    let kinds: DescriptorKind[] = ["wpkh", "sh-wpkh", "pkh", "tr"];
    if (EXTENDED_KEY.test(encoded)) {
        try { key = bip32.fromBase58(toXpub(encoded), networks.bitcoin).toBase58() + "/<0;1>/*"; }
        catch { throw new Error("Invalid mainnet extended key"); }
        if (encoded[0] === "z") kinds = ["wpkh"];
        if (encoded[0] === "y") kinds = ["sh-wpkh"];
    } else if (WIF.test(encoded) || HEX_PUBKEY.test(encoded)) {
        key = encoded;
    } else {
        return undefined;
    }
    return kinds.map(kind => {
        const expression = `${origin}${key}`;
        return parseDescriptor(kind === "sh-wpkh" ? `sh(wpkh(${expression}))` : `${kind}(${expression})`);
    });
}

// Path from the master key to `key`, for signing with a seed. Without a key origin, a single-sig
// account-level xpub is assumed to sit at the standard path for its type (m/84'/0'/n' etc.);
// the signer checks the derived key against the xpub before using it.
export function accountPath(descriptor: Descriptor, key: DescriptorKey): string | undefined {
    if (key.hasOrigin) return key.originPath;
    const purpose = STANDARD_PURPOSE[descriptor.kind];
    if (purpose === undefined || !key.xpub || key.xpub.depth !== 3 || key.xpub.index < 0x80000000) return undefined;
    return `m/${purpose}'/0'/${key.xpub.index - 0x80000000}'`;
}
