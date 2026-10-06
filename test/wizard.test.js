const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const bip39 = require("bip39");
const ecc = require("tiny-secp256k1");
const { ECPairFactory } = require("ecpair");
const { Transaction, payments, networks, script: bscript } = require("bitcoinjs-lib");
const { bip32 } = require("../dist/bip32");
const { parseDescriptor } = require("../dist/wizard/descriptor");

const ECPair = ECPairFactory(ecc);
const ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DEST = payments.p2wpkh({ pubkey: ECPair.fromPrivateKey(Buffer.alloc(32, 7)).publicKey, network: networks.bitcoin }).address;

let pass = 0;
async function test(name, fn) {
    try {
        await fn();
        pass++;
        console.log(`PASS ${name}`);
    } catch (error) {
        console.error(`FAIL ${name}\n${error.stack}`);
        process.exit(1);
    }
}

// Derived directly (not through the hot signer) so descriptor tests stand on their own.
function rootOf(mnemonic, passphrase = "") {
    return bip32.fromSeed(bip39.mnemonicToSeedSync(mnemonic, passphrase), networks.bitcoin);
}

function singleSig(kind, purpose, mnemonic = ABANDON, passphrase = "", suffix = "<0;1>/*") {
    const root = rootOf(mnemonic, passphrase);
    const origin = `${root.fingerprint.toString("hex")}/${purpose}h/0h/0h`;
    const xpub = root.derivePath(`m/${purpose}'/0'/0'`).neutered().toBase58();
    const key = `[${origin}]${xpub}/${suffix}`;
    const text = kind === "sh-wpkh" ? `sh(wpkh(${key}))` : `${kind}(${key})`;
    return { root, descriptor: parseDescriptor(text) };
}

(async () => {
    await test("BIP84 vector and checksum", () => {
        const { descriptor } = singleSig("wpkh", 84);
        assert.strictEqual(descriptor.derive(0, 0).address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert.strictEqual(descriptor.derive(1, 0).address, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
        assert.strictEqual(descriptor.branches, 2);
        const bip380 = parseDescriptor("pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)#ml40v0wf");
        assert.strictEqual(bip380.derive(0, 0).keys[0].path, "m/44'/0'/0'/1/0");
        assert.throws(() => parseDescriptor(descriptor.text.slice(0, -1) + "x"), /checksum/);
    });

    await test("receive-only descriptor also scans change", () => {
        const { descriptor } = singleSig("tr", 86, ABANDON, "", "0/*");
        assert.ok(descriptor.addedChange);
        assert.strictEqual(descriptor.branches, 2);
        assert.strictEqual(descriptor.derive(0, 0).address, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
        assert.strictEqual(descriptor.derive(1, 0).keys[0].path, "m/86'/0'/0'/1/0");
    });

    await test("descriptor id ignores hardened marker style and checksum", () => {
        const a = singleSig("wpkh", 84).descriptor;
        const b = parseDescriptor(a.text.split("#")[0].replace(/(\d)h/g, "$1'"));
        assert.strictEqual(a.id, b.id);
    });

    console.log(`\n${pass} wizard tests passed.`);
})();
