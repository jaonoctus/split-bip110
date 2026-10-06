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
const { scanDescriptor, writeScanFile, findLatestScan } = require("../dist/wizard/scan");
const { assertChain } = require("../dist/wizard/backend");
const { BIP110, BITCOIN } = require("../dist/wizard/chain");
const { UTXOHelper } = require("../dist/helper/utxo-helper");

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

// In-memory backend: `funded` maps "branch/index" to UTXO lists; `used` lists other addresses with history.
function fakeBackend(descriptor, funded, used = []) {
    const byAddress = new Map();
    for (const [key, utxos] of Object.entries(funded)) {
        const [branch, index] = key.split("/").map(Number);
        byAddress.set(descriptor.derive(branch, index).address, utxos);
    }
    const history = new Set([...byAddress.keys(), ...used.map(k => { const [b, i] = k.split("/").map(Number); return descriptor.derive(b, i).address; })]);
    const calls = { hasHistory: 0, listUnspent: 0 };
    return {
        calls,
        label: "fake",
        async hasHistory(address) { calls.hasHistory++; return history.has(address); },
        async listUnspent(address) { calls.listUnspent++; return byAddress.get(address) ?? []; },
        async getRawTransaction() { throw new Error("unused"); },
        async recommendedFeeRate() { return undefined; },
        async blockHash() { return "00000000000000000000c705b7a0a847d2713d73da4a1b20cea3dfdd617fa651"; },
        close() {},
    };
}

function coinFor(descriptor, branch, index, value, txid = "ab".repeat(32), vout = 0) {
    return { txid, vout, value, address: descriptor.derive(branch, index).address, branch, index, confirmed: true };
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

    await test("gap scan finds coins and stops after the gap", async () => {
        const { descriptor } = singleSig("wpkh", 84);
        const backend = fakeBackend(descriptor, {
            "0/0": [{ txid: "01".repeat(32), vout: 1, value: 5000, confirmed: true, blockTime: 1786000000 }],
            "0/7": [{ txid: "02".repeat(32), vout: 0, value: 7000, confirmed: false }],
            "1/2": [{ txid: "03".repeat(32), vout: 3, value: 9000, confirmed: true }],
        }, ["0/3"]);
        const result = await scanDescriptor(descriptor, backend, { gapLimit: 5, concurrency: 3 });
        assert.deepStrictEqual(result.coins.map(c => `${c.branch}/${c.index}`), ["0/0", "0/7", "1/2"]);
        assert.deepStrictEqual(result.lastUsed, [7, 2]);

        // A refresh only re-checks known coin addresses and continues after the last used index.
        const later = fakeBackend(descriptor, {
            "0/7": [{ txid: "02".repeat(32), vout: 0, value: 7000, confirmed: true }],
            "0/9": [{ txid: "04".repeat(32), vout: 0, value: 1000, confirmed: true }],
        });
        const refreshed = await scanDescriptor(descriptor, later, { gapLimit: 5, concurrency: 1 }, result);
        assert.deepStrictEqual(refreshed.coins.map(c => `${c.branch}/${c.index}`), ["0/7", "0/9"]);
        assert.deepStrictEqual(refreshed.lastUsed, [9, 2]);
        assert.strictEqual(later.calls.hasHistory, 7 + 5);
    });

    await test("scan files never overwrite and stay readable by the legacy parser", async () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "split-bip110-"));
        const { descriptor } = singleSig("wpkh", 84);
        const other = singleSig("tr", 86).descriptor;
        const scan = { coins: [coinFor(descriptor, 0, 4, 123456789)], lastUsed: [4, -1], addressesChecked: 30 };
        const now = new Date("2026-10-06T12:00:00Z");
        const first = writeScanFile(dir, BIP110, descriptor, "fake", scan, now);
        const second = writeScanFile(dir, BIP110, descriptor, "fake", { ...scan, lastUsed: [5, -1] }, now);
        const third = writeScanFile(dir, BIP110, other, "fake", { coins: [], lastUsed: [-1, -1], addressesChecked: 0 }, now);
        assert.notStrictEqual(first, second);
        assert.ok(path.basename(first).startsWith(`delete_later_73c5da0a_${descriptor.id}_20261006T120000Z`));
        assert.strictEqual(fs.readdirSync(dir).length, 3);

        const { scan: latest } = findLatestScan(dir, BIP110, descriptor);
        assert.strictEqual(latest.file, second);
        assert.deepStrictEqual(latest.lastUsed, [5, -1]);
        assert.strictEqual(latest.coins[0].value, 123456789);
        assert.strictEqual(findLatestScan(dir, BIP110, other).scan.file, third);

        // Bitcoin scans of the same descriptor live in their own files and never mix with BIP110 ones.
        assert.strictEqual(findLatestScan(dir, BITCOIN, descriptor).scan, undefined);
        const btc = writeScanFile(dir, BITCOIN, descriptor, "fake", { ...scan, lastUsed: [9, -1] }, new Date("2026-10-07T00:00:00Z"));
        assert.ok(path.basename(btc).startsWith(`delete_later_btc_73c5da0a_${descriptor.id}_`));
        assert.strictEqual(findLatestScan(dir, BITCOIN, descriptor).scan.file, btc);
        assert.strictEqual(findLatestScan(dir, BIP110, descriptor).scan.file, second);

        const legacy = new UTXOHelper(first).parse();
        assert.strictEqual(legacy[0][0].amount, 123456789);
        assert.strictEqual(legacy[0][0].address, descriptor.derive(0, 4).address);
    });

    await test("a scan file that names another descriptor's address is rejected", () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "split-bip110-"));
        const { descriptor } = singleSig("wpkh", 84);
        const file = writeScanFile(dir, BIP110, descriptor, "fake", { coins: [coinFor(descriptor, 0, 1, 1000)], lastUsed: [1, -1], addressesChecked: 1 });
        fs.chmodSync(file, 0o600);
        const tampered = fs.readFileSync(file, "utf8").replace(",0/1,", ",0/2,");
        fs.writeFileSync(file, tampered);
        const { scan, errors } = findLatestScan(dir, BIP110, descriptor);
        assert.strictEqual(scan, undefined);
        assert.match(errors[0], /does not derive/);
    });

    await test("servers on another chain are refused", async () => {
        const { descriptor } = singleSig("wpkh", 84);
        const bip110 = fakeBackend(descriptor, {});
        await assertChain(bip110, BIP110);
        await assert.rejects(assertChain(bip110, BITCOIN), /not on the Bitcoin \(BTC\) chain/);
        const btc = { ...bip110, label: "btc", async blockHash() { return BITCOIN.checkHash; } };
        await assertChain(btc, BITCOIN);
        await assert.rejects(assertChain(btc, BIP110), /not on the BIP110 chain/);
    });

    console.log(`\n${pass} wizard tests passed.`);
})();
