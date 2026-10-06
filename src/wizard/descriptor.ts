import { createHash } from "crypto";
import { BIP32Interface } from "bip32";
import { networks, payments } from "bitcoinjs-lib";
import { bip32 } from "../bip32";
import { ScriptType } from "../script-type";

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
    // Master fingerprint from the key origin, or the xpub's own fingerprint when there is no origin.
    fingerprint: Buffer;
    hasOrigin: boolean;
    // Path from the master key to the xpub, e.g. "m/84'/0'/0'" ("m" without origin).
    originPath: string;
    xpub: BIP32Interface;
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
    // Descriptor as given by the user, with checksum.
    text: string;
    // Stable identifier: sha256 of the body with hardened markers normalized to "h".
    id: string;
    kind: DescriptorKind;
    scriptType: ScriptType;
    // Signatures required; 1 for single-sig.
    threshold: number;
    keys: DescriptorKey[];
    branches: number;
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

function parseKey(expression: string): DescriptorKey {
    const match = /^(?:\[([^\]]+)\])?([xyz]pub[1-9A-HJ-NP-Za-km-z]+)(.*)$/.exec(expression);
    if (!match) throw new Error("Descriptor key must be a mainnet xpub, optionally with key origin");
    const [, origin, encoded, suffix] = match;
    if (!encoded.startsWith("xpub")) throw new Error("Descriptor keys must be xpubs (convert ypub/zpub to xpub)");
    let fingerprint: Buffer | undefined;
    let originPath = "m";
    if (origin) {
        const originMatch = /^([0-9a-fA-F]{8})((?:\/(?:0|[1-9]\d*)(?:h|H|')?)*)$/.exec(origin);
        if (!originMatch) throw new Error("Invalid descriptor key origin");
        fingerprint = Buffer.from(originMatch[1], "hex");
        originPath = "m" + originMatch[2].replace(/[hH]/g, "'");
    }
    let xpub: BIP32Interface;
    try { xpub = bip32.fromBase58(encoded, networks.bitcoin); }
    catch { throw new Error("Invalid mainnet xpub in descriptor"); }
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
    function branchNode(keyIndex: number, branch: number): BIP32Interface {
        let node = branchNodes[keyIndex].get(branch);
        if (!node) {
            node = keys[keyIndex].xpub;
            for (const step of stepsForBranch(keys[keyIndex], branch)) node = node.derive(step);
            branchNodes[keyIndex].set(branch, node);
        }
        return node;
    }

    const network = networks.bitcoin;
    const id = createHash("sha256").update(body.replace(/['H]/g, "h")).digest("hex").slice(0, 16);

    return {
        text: `${body}#${checksum}`,
        id,
        kind,
        scriptType,
        threshold,
        keys,
        branches,
        addedChange,
        branchStep(branch) {
            const step = keys[0].steps.find(s => Array.isArray(s));
            return Array.isArray(step) ? String(step[branch]) : String(branch);
        },
        derive(branch, index) {
            if (!Number.isSafeInteger(branch) || branch < 0 || branch >= branches ||
                !Number.isSafeInteger(index) || index < 0 || index >= 0x80000000) {
                throw new Error("Descriptor branch or index out of range");
            }
            const derived: DerivedKey[] = keys.map((key, keyIndex) => ({
                key,
                pubkey: branchNode(keyIndex, branch).derive(index).publicKey,
                path: [key.originPath, ...stepsForBranch(key, branch), index].join("/"),
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
