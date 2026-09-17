const { Psbt, payments, networks, initEccLib, script: bscript } = require("bitcoinjs-lib");
const { ECPairFactory } = require("ecpair");
const ecc = require("tiny-secp256k1");
const { signInputsUnified } = require("../dist/helper/unified-signer");
const { unifiedSighash, SigVersion, SIGHASH_ALL, SIGHASH_UNIFIED } = require("../dist/helper/unified-sighash");
const { UTXO } = require("../dist/model/utxo");
const { ScriptTypeEnum } = require("../dist/script-type");

initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const NETWORK = networks.bitcoin;
const HASH_TYPE = SIGHASH_ALL | SIGHASH_UNIFIED;

const privkey = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
const pair = ECPair.fromPrivateKey(privkey);

const recipient = ECPair.fromPrivateKey(Buffer.alloc(32, 7)).publicKey;

function fakeUtxo(scriptEnum, address) {
    return new UTXO("0000000000000000000000000000000000000000000000000000000000000001", 0, 100000, address);
}

function derToCompact(der) {
    // Skip the 0x30 len 0x02 rLen r 0x02 sLen s framing.
    const rLen = der[3];
    const rStart = 4;
    const rEnd = rStart + rLen;
    const sLen = der[rEnd + 1];
    const sStart = rEnd + 2;
    let r = der.subarray(rStart, rEnd);
    let s = der.subarray(sStart, sStart + sLen);
    // Strip leading zero padding bytes, then pad to 32.
    while (r.length > 1 && r[0] === 0) r = r.subarray(1);
    while (s.length > 1 && s[0] === 0) s = s.subarray(1);
    const r32 = Buffer.concat([Buffer.alloc(32 - r.length), r]);
    const s32 = Buffer.concat([Buffer.alloc(32 - s.length), s]);
    return Buffer.concat([r32, s32]);
}

const cases = [
    { enum: ScriptTypeEnum.P2PKH, address: payments.p2pkh({ pubkey: pair.publicKey, network: NETWORK }).address },
    { enum: ScriptTypeEnum.P2SH, address: payments.p2sh({ redeem: payments.p2wpkh({ pubkey: pair.publicKey, network: NETWORK }), network: NETWORK }).address },
    { enum: ScriptTypeEnum.P2WPKH, address: payments.p2wpkh({ pubkey: pair.publicKey, network: NETWORK }).address },
    { enum: ScriptTypeEnum.P2TR, address: payments.p2tr({ internalPubkey: pair.publicKey.subarray(1), network: NETWORK }).address },
];

let pass = 0;
let fail = 0;

for (const c of cases) {
    const utxo = fakeUtxo(c.enum, c.address);
    const psbt = new Psbt({ network: NETWORK });
    const input = { hash: utxo.txid, index: utxo.vout, sequence: 0xfffffffd, witnessUtxo: { script: utxo.output, value: utxo.amount } };
    if (c.enum === ScriptTypeEnum.P2SH) {
        input.redeemScript = payments.p2wpkh({ pubkey: pair.publicKey, network: NETWORK }).output;
    } else if (c.enum === ScriptTypeEnum.P2TR) {
        input.tapInternalKey = pair.publicKey.subarray(1);
    }
    psbt.addInput(input);
    psbt.addOutput({ address: payments.p2wpkh({ pubkey: recipient, network: NETWORK }).address, value: 99900 });

    signInputsUnified(psbt, [utxo], new Map([[utxo, privkey]]));

    let extractOk = false;
    let verifyOk = false;
    let detail = "";
    try {
        const tx = psbt.extractTransaction();
        extractOk = true;

        // Independently reconstruct the digest the signer should have used,
        // per script type, then verify the produced signature against it.
        let sigVersion;
        let scriptCode;
        if (c.enum === ScriptTypeEnum.P2PKH) {
            sigVersion = SigVersion.BASE;
            scriptCode = utxo.output;
        } else if (c.enum === ScriptTypeEnum.P2WPKH) {
            sigVersion = SigVersion.WITNESS_V0;
            scriptCode = payments.p2pkh({ hash: utxo.output.subarray(2) }).output;
        } else if (c.enum === ScriptTypeEnum.P2SH) {
            sigVersion = SigVersion.WITNESS_V0;
            scriptCode = payments.p2pkh({ pubkey: pair.publicKey }).output;
        } else {
            sigVersion = SigVersion.TAPROOT;
        }

        const spentOutputs = [{ value: utxo.amount, scriptPubKey: utxo.output }];
        const digest = unifiedSighash(tx, 0, HASH_TYPE, sigVersion, spentOutputs, scriptCode ? { scriptCode } : {});

        let sigBuf, pub;
        if (c.enum === ScriptTypeEnum.P2PKH) {
            const decomp = bscript.decompile(tx.ins[0].script);
            sigBuf = decomp[0];
            pub = decomp[1];
        } else if (c.enum === ScriptTypeEnum.P2TR) {
            sigBuf = tx.ins[0].witness[0];
            pub = utxo.output.subarray(2);
        } else {
            sigBuf = tx.ins[0].witness[0];
            pub = tx.ins[0].witness[1];
        }

        if (c.enum === ScriptTypeEnum.P2TR) {
            verifyOk = ecc.verifySchnorr(digest, pub, sigBuf.subarray(0, 64));
        } else {
            verifyOk = ecc.verify(digest, pub, derToCompact(sigBuf.subarray(0, sigBuf.length - 1)));
        }
        if (!verifyOk) detail = "signature did not verify against independently-computed digest";
    } catch (e) {
        detail = e.message;
    }

    if (extractOk && verifyOk) {
        console.log(`PASS ScriptTypeEnum.${c.enum} -> extract OK, sig verified`);
        pass++;
    } else {
        console.log(`FAIL ScriptTypeEnum.${c.enum} -> extract=${extractOk} verify=${verifyOk} ${detail}`);
        fail++;
    }
}

console.log(`\n${pass}/${pass + fail} smoke-sign cases passed.`);
if (fail > 0) process.exit(1);
