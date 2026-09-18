import { Psbt, crypto, payments, script as bscript } from "bitcoinjs-lib";
import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";
import { UTXO } from "../model/utxo";
import { ScriptTypeEnum } from "../script-type";
import { SigVersion, unifiedSighash, SIGHASH_ALL, SIGHASH_UNIFIED } from "./unified-sighash";

const ECPair = ECPairFactory(ecc);

const HASH_TYPE = SIGHASH_ALL | SIGHASH_UNIFIED;

function varInt(value: number): Buffer {
    if (value < 0xfd) {
        const buffer = Buffer.alloc(1);
        buffer.writeUInt8(value, 0);
        return buffer;
    }
    if (value < 0x10000) {
        const buffer = Buffer.alloc(3);
        buffer.writeUInt8(0xfd, 0);
        buffer.writeUInt16LE(value, 1);
        return buffer;
    }
    const buffer = Buffer.alloc(5);
    buffer.writeUInt8(0xfe, 0);
    buffer.writeUInt32LE(value, 1);
    return buffer;
}

function witnessStackToScriptWitness(witness: Buffer[]): Buffer {
    const parts: Buffer[] = [varInt(witness.length)];
    for (const item of witness) {
        parts.push(varInt(item.length), item);
    }
    return Buffer.concat(parts);
}

function derInt(value: Buffer): Buffer {
    let i = 0;
    while (value[i] === 0) i++;
    if (i === value.length) return Buffer.from([0x00]);
    const trimmed = value.subarray(i);
    return trimmed[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), trimmed]) : trimmed;
}

function derSignature(r: Buffer, s: Buffer): Buffer {
    const rEnc = derInt(r);
    const sEnc = derInt(s);
    const buffer = Buffer.alloc(6 + rEnc.length + sEnc.length);
    buffer[0] = 0x30;
    buffer[1] = buffer.length - 2;
    buffer[2] = 0x02;
    buffer[3] = rEnc.length;
    rEnc.copy(buffer, 4);
    buffer[4 + rEnc.length] = 0x02;
    buffer[5 + rEnc.length] = sEnc.length;
    sEnc.copy(buffer, 6 + rEnc.length);
    return buffer;
}

// Encode a 64-byte compact (r||s) signature as DER + hash type byte.
function scriptSignature(signature: Buffer, hashType: number): Buffer {
    return Buffer.concat([derSignature(signature.subarray(0, 32), signature.subarray(32)), Buffer.from([hashType])]);
}

export function signInputsUnified(psbt: Psbt, utxos: UTXO[], privkeyMap: Map<UTXO, Buffer[]>): void {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tx = (psbt as any).__CACHE.__TX;
    const spentOutputs = utxos.map(u => ({ value: u.amount, scriptPubKey: u.output }));

    for (let i = 0; i < utxos.length; i++) {
        const utxo = utxos[i];
        const privkeys = privkeyMap.get(utxo);
        if (!privkeys || privkeys.length === 0) {
            throw new Error(`No private key found for UTXO ${utxo.prevout}`);
        }

        const typeEnum = utxo.scriptType.typeEnum;

        let sigVersion: SigVersion;
        let scriptCode: Buffer | undefined;

        if (typeEnum === ScriptTypeEnum.P2PKH) {
            sigVersion = SigVersion.BASE;
            scriptCode = utxo.output;
        } else if (typeEnum === ScriptTypeEnum.P2WPKH) {
            sigVersion = SigVersion.WITNESS_V0;
            scriptCode = payments.p2pkh({ hash: utxo.output.subarray(2) }).output;
        } else if (typeEnum === ScriptTypeEnum.P2SH) {
            sigVersion = SigVersion.WITNESS_V0;
            const pubkey = ECPair.fromPrivateKey(privkeys[0]).publicKey;
            scriptCode = payments.p2pkh({ pubkey }).output;
        } else if (typeEnum === ScriptTypeEnum.P2WSH) {
            sigVersion = SigVersion.WITNESS_V0;
            scriptCode = utxo.witnessScript;
        } else {
            sigVersion = SigVersion.TAPROOT;
        }

        const digest = unifiedSighash(tx, i, HASH_TYPE, sigVersion, spentOutputs, { scriptCode });

        let finalScriptSig: Buffer | undefined;
        let finalScriptWitness: Buffer | undefined;

        if (typeEnum === ScriptTypeEnum.P2TR) {
            const pair = ECPair.fromPrivateKey(privkeys[0]);
            const pubkey = pair.publicKey;
            const tweaked = pair.tweak(crypto.taggedHash("TapTweak", pubkey.subarray(1)));
            finalScriptWitness = witnessStackToScriptWitness([Buffer.concat([tweaked.signSchnorr(digest), Buffer.from([HASH_TYPE])])]);
        } else if (typeEnum === ScriptTypeEnum.P2WSH) {
            const threshold = utxo.threshold;
            const witnessScript = utxo.witnessScript as Buffer;
            const witnessItems: Buffer[] = [Buffer.alloc(0)];
            for (let j = 0; j < threshold; j++) {
                const pair = ECPair.fromPrivateKey(privkeys[j]);
                const sig = scriptSignature(pair.sign(digest), HASH_TYPE);
                witnessItems.push(sig);
            }
            witnessItems.push(witnessScript);
            finalScriptWitness = witnessStackToScriptWitness(witnessItems);
        } else {
            const pair = ECPair.fromPrivateKey(privkeys[0]);
            const pubkey = pair.publicKey;
            const sig = scriptSignature(pair.sign(digest), HASH_TYPE);
            if (typeEnum === ScriptTypeEnum.P2PKH) {
                finalScriptSig = bscript.compile([sig, pubkey]);
            } else if (typeEnum === ScriptTypeEnum.P2WPKH) {
                finalScriptWitness = witnessStackToScriptWitness([sig, pubkey]);
            } else {
                finalScriptSig = bscript.compile([payments.p2wpkh({ pubkey }).output as Buffer]);
                finalScriptWitness = witnessStackToScriptWitness([sig, pubkey]);
            }
        }

        const update: { finalScriptSig?: Buffer; finalScriptWitness?: Buffer } = {};
        if (finalScriptSig) update.finalScriptSig = finalScriptSig;
        if (finalScriptWitness) update.finalScriptWitness = finalScriptWitness;
        psbt.updateInput(i, update);
    }
}