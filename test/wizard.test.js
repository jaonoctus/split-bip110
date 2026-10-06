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
const { buildPlan, groupCoins, linkageWarnings, estimateVsize, verifyParent } = require("../dist/wizard/builder");
const { assertChain } = require("../dist/wizard/backend");
const { BIP110, BITCOIN } = require("../dist/wizard/chain");
const { matchKeys, rootFromMnemonic, signPlan, mnemonicProblem } = require("../dist/wizard/hot-signer");
const { unifiedSighash, SigVersion } = require("../dist/helper/unified-sighash");
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

const MULTISIG_MNEMONICS = ["00", "11", "22"].map(b => bip39.entropyToMnemonic(b.repeat(16)));
function multisig() {
    const roots = MULTISIG_MNEMONICS.map(m => rootOf(m));
    const keys = roots.map(r => `[${r.fingerprint.toString("hex")}/48h/0h/0h/2h]${r.derivePath("m/48'/0'/0'/2'").neutered().toBase58()}/<0;1>/*`);
    return { roots, descriptor: parseDescriptor(`wsh(sortedmulti(2,${keys.join(",")}))`) };
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

    await test("grouping and privacy warnings", () => {
        const { descriptor } = singleSig("wpkh", 84);
        const a1 = coinFor(descriptor, 0, 0, 50000, "01".repeat(32));
        const a2 = coinFor(descriptor, 0, 0, 60000, "02".repeat(32));
        const b = coinFor(descriptor, 0, 1, 70000, "03".repeat(32));
        const separate = groupCoins([a1, a2, b], "separate");
        assert.deepStrictEqual(separate.map(g => g.length), [2, 1]);

        const xpubDest = { kind: "xpub", account: bip32.fromSeed(Buffer.alloc(32, 9)).neutered(), scriptType: require("../dist/script-type").ScriptType.P2WPKH, startIndex: 0 };
        const planX = buildPlan(descriptor, separate, xpubDest, 2, new Map());
        assert.deepStrictEqual(linkageWarnings(planX, xpubDest), []);
        assert.notStrictEqual(planX[0].address, planX[1].address);

        const addrDest = { kind: "address", address: DEST };
        assert.strictEqual(linkageWarnings(buildPlan(descriptor, separate, addrDest, 2, new Map()), addrDest).length, 1);
        const consolidated = buildPlan(descriptor, groupCoins([a1, a2, b], "consolidate"), xpubDest, 2, new Map());
        assert.strictEqual(linkageWarnings(consolidated, xpubDest).length, 1);
    });

    await test("dust outputs are refused", () => {
        const { descriptor } = singleSig("wpkh", 84);
        assert.throws(() => buildPlan(descriptor, [[coinFor(descriptor, 0, 0, 400)]], { kind: "address", address: DEST }, 2, new Map()), /dust/);
    });

    await test("seed matching needs the right passphrase", () => {
        const { descriptor } = singleSig("wpkh", 84, ABANDON, "secret");
        assert.deepStrictEqual(matchKeys(descriptor, rootFromMnemonic(ABANDON, "secret")), [0]);
        assert.deepStrictEqual(matchKeys(descriptor, rootFromMnemonic(ABANDON, "")), []);
        assert.strictEqual(mnemonicProblem(ABANDON), undefined);
        assert.match(mnemonicProblem(ABANDON.replace("about", "abandon")), /Checksum/);
        assert.match(mnemonicProblem("zzz " + ABANDON), /1 word/);
    });

    // bitcoinjs refuses to decode hash type 0x21, so unpack the DER signature here.
    function derToCompact(der) {
        const rLen = der[3];
        const r = der.subarray(4, 4 + rLen);
        const s = der.subarray(6 + rLen, 6 + rLen + der[5 + rLen]);
        const pad = n => Buffer.concat([Buffer.alloc(32), n.subarray(n[0] === 0 ? 1 : 0)]).subarray(-32);
        return Buffer.concat([pad(r), pad(s)]);
    }

    function verifyInputs(descriptor, plan, txs) {
        for (const [t, tx] of txs.entries()) {
            const coins = plan[t].coins;
            const spent = coins.map(c => ({ value: c.value, scriptPubKey: descriptor.derive(c.branch, c.index).output }));
            for (const [i, coin] of coins.entries()) {
                const derived = descriptor.derive(coin.branch, coin.index);
                const witness = tx.ins[i].witness;
                if (descriptor.kind === "tr") {
                    const sig = witness[0];
                    assert.strictEqual(sig[64], 0x21);
                    const digest = unifiedSighash(tx, i, 0x21, SigVersion.TAPROOT, spent);
                    assert.ok(ecc.verifySchnorr(digest, derived.output.subarray(2), sig.subarray(0, 64)));
                    continue;
                }
                let sigs, pubkeys, sigVersion, scriptCode;
                if (descriptor.kind === "pkh") {
                    const chunks = bscript.decompile(tx.ins[i].script);
                    sigs = [chunks[0]]; pubkeys = [chunks[1]]; sigVersion = SigVersion.BASE; scriptCode = derived.output;
                } else if (descriptor.kind === "wsh-sortedmulti") {
                    sigs = witness.slice(1, -1); sigVersion = SigVersion.WITNESS_V0; scriptCode = derived.witnessScript;
                    pubkeys = payments.p2ms({ output: derived.witnessScript }).pubkeys;
                } else {
                    sigs = [witness[0]]; pubkeys = [witness[1]]; sigVersion = SigVersion.WITNESS_V0;
                    scriptCode = payments.p2pkh({ pubkey: witness[1] }).output;
                }
                const digest = unifiedSighash(tx, i, 0x21, sigVersion, spent, { scriptCode });
                // Each signature must verify against a later pubkey than the previous one (CHECKMULTISIG order).
                let k = 0;
                for (const sig of sigs) {
                    assert.strictEqual(sig[sig.length - 1], 0x21);
                    const compact = derToCompact(sig.subarray(0, -1));
                    while (k < pubkeys.length && !ecc.verify(digest, pubkeys[k], compact)) k++;
                    assert.ok(k < pubkeys.length, `signature ${i} does not verify in order`);
                    k++;
                }
            }
        }
    }

    for (const [kind, purpose] of [["wpkh", 84], ["sh-wpkh", 49], ["tr", 86], ["pkh", 44]]) {
        await test(`hot signing ${kind} matches the estimate and verifies`, () => {
            const { root, descriptor } = singleSig(kind, purpose);
            const coins = [coinFor(descriptor, 0, 2, 100000, "0a".repeat(32), 1), coinFor(descriptor, 1, 5, 200000, "0b".repeat(32), 0)];
            const parents = new Map();
            if (kind === "pkh") {
                coins.forEach(coin => {
                    const parent = new Transaction();
                    parent.addInput(Buffer.alloc(32, coin.index), 0);
                    parent.addOutput(Buffer.from("6a", "hex"), 0);
                    parent.addOutput(descriptor.derive(coin.branch, coin.index).output, coin.value);
                    coin.txid = parent.getId();
                    coin.vout = 1;
                    parents.set(coin.txid, verifyParent(coin, parent.toHex(), descriptor.derive(coin.branch, coin.index).output));
                });
                assert.throws(() => verifyParent({ ...coins[0], value: 1 }, parents.get(coins[0].txid).toString("hex"), descriptor.derive(0, 2).output), /does not match/);
            }
            const plan = buildPlan(descriptor, groupCoins(coins, "consolidate"), { kind: "address", address: DEST }, 3, parents);
            const psbtInput = plan[0].psbt.data.inputs[0];
            assert.strictEqual(psbtInput.sighashType, 0x21);
            assert.ok(kind === "tr" ? psbtInput.tapBip32Derivation : psbtInput.bip32Derivation);
            const txs = signPlan(descriptor, plan, new Map([[0, root]]));
            const vsize = txs[0].virtualSize();
            assert.ok(vsize <= plan[0].vsize && vsize >= plan[0].vsize - 3, `vsize ${vsize} vs estimate ${plan[0].vsize}`);
            assert.strictEqual(txs[0].outs[0].value, 300000 - plan[0].fee);
            verifyInputs(descriptor, plan, txs);
        });
    }

    await test("hot signing 2-of-3 multisig with keys 2 and 3", () => {
        const { roots, descriptor } = multisig();
        assert.deepStrictEqual(matchKeys(descriptor, roots[2]), [2]);
        const coins = [coinFor(descriptor, 0, 0, 100000), coinFor(descriptor, 1, 3, 100000, "cd".repeat(32))];
        const plan = buildPlan(descriptor, groupCoins(coins, "separate"), { kind: "address", address: DEST }, 1.5, new Map());
        const txs = signPlan(descriptor, plan, new Map([[1, roots[1]], [2, roots[2]]]));
        for (const [i, tx] of txs.entries()) {
            assert.ok(tx.virtualSize() <= plan[i].vsize && tx.virtualSize() >= plan[i].vsize - 3);
            assert.strictEqual(tx.ins[0].witness.length, 4);
        }
        verifyInputs(descriptor, plan, txs);
        assert.strictEqual(estimateVsize(descriptor, 1, Buffer.alloc(22)), plan[0].vsize);
    });

    // Verifies standard BTC signatures with bitcoinjs's own sighash code (independent of the unified signer).
    function verifyStandard(descriptor, plan, txs) {
        for (const [t, tx] of txs.entries()) {
            const coins = plan[t].coins;
            const scripts = coins.map(c => descriptor.derive(c.branch, c.index).output);
            const values = coins.map(c => c.value);
            for (const [i, coin] of coins.entries()) {
                const derived = descriptor.derive(coin.branch, coin.index);
                const witness = tx.ins[i].witness;
                if (descriptor.kind === "tr") {
                    assert.strictEqual(witness[0].length, 64, "SIGHASH_DEFAULT signatures have no hash type byte");
                    const digest = tx.hashForWitnessV1(i, scripts, values, Transaction.SIGHASH_DEFAULT);
                    assert.ok(ecc.verifySchnorr(digest, derived.output.subarray(2), witness[0]));
                    continue;
                }
                let sigs, pubkeys, digest;
                if (descriptor.kind === "pkh") {
                    const chunks = bscript.decompile(tx.ins[i].script);
                    sigs = [chunks[0]]; pubkeys = [chunks[1]];
                    digest = tx.hashForSignature(i, derived.output, Transaction.SIGHASH_ALL);
                } else if (descriptor.kind === "wsh-sortedmulti") {
                    sigs = witness.slice(1, -1);
                    pubkeys = payments.p2ms({ output: derived.witnessScript }).pubkeys;
                    digest = tx.hashForWitnessV0(i, derived.witnessScript, coin.value, Transaction.SIGHASH_ALL);
                } else {
                    sigs = [witness[0]]; pubkeys = [witness[1]];
                    digest = tx.hashForWitnessV0(i, payments.p2pkh({ pubkey: witness[1] }).output, coin.value, Transaction.SIGHASH_ALL);
                }
                let k = 0;
                for (const sig of sigs) {
                    const decoded = bscript.signature.decode(sig);
                    assert.strictEqual(decoded.hashType, Transaction.SIGHASH_ALL);
                    while (k < pubkeys.length && !ecc.verify(digest, pubkeys[k], decoded.signature)) k++;
                    assert.ok(k < pubkeys.length, `signature ${i} does not verify in order`);
                    k++;
                }
            }
        }
    }

    for (const [kind, purpose] of [["wpkh", 84], ["sh-wpkh", 49], ["tr", 86], ["pkh", 44]]) {
        await test(`standard BTC signing ${kind}`, () => {
            const { root, descriptor } = singleSig(kind, purpose);
            const coins = [coinFor(descriptor, 0, 2, 100000, "0a".repeat(32), 1), coinFor(descriptor, 1, 5, 200000, "0b".repeat(32), 0)];
            const parents = new Map();
            if (kind === "pkh") {
                coins.forEach(coin => {
                    const parent = new Transaction();
                    parent.addInput(Buffer.alloc(32, coin.index), 0);
                    parent.addOutput(descriptor.derive(coin.branch, coin.index).output, coin.value);
                    coin.txid = parent.getId();
                    coin.vout = 0;
                    parents.set(coin.txid, parent.toBuffer());
                });
            }
            const plan = buildPlan(descriptor, groupCoins(coins, "consolidate"), { kind: "address", address: DEST }, 3, parents, "standard");
            assert.strictEqual(plan[0].psbt.data.inputs[0].sighashType, undefined);
            const txs = signPlan(descriptor, plan, new Map([[0, root]]), "standard");
            const vsize = txs[0].virtualSize();
            assert.ok(vsize <= plan[0].vsize && vsize >= plan[0].vsize - 3, `vsize ${vsize} vs estimate ${plan[0].vsize}`);
            verifyStandard(descriptor, plan, txs);
        });
    }

    await test("standard BTC signing 2-of-3 multisig with keys 1 and 3", () => {
        const { roots, descriptor } = multisig();
        const coins = [coinFor(descriptor, 0, 0, 100000), coinFor(descriptor, 1, 3, 100000, "cd".repeat(32))];
        const plan = buildPlan(descriptor, groupCoins(coins, "separate"), { kind: "address", address: DEST }, 1.5, new Map(), "standard");
        const txs = signPlan(descriptor, plan, new Map([[0, roots[0]], [2, roots[2]]]), "standard");
        verifyStandard(descriptor, plan, txs);
    });

    await test("descriptor destination gives a fresh address per transaction", () => {
        const { descriptor } = singleSig("wpkh", 84);
        const target = singleSig("tr", 86, MULTISIG_MNEMONICS[0]).descriptor;
        const coins = [coinFor(descriptor, 0, 0, 50000, "01".repeat(32)), coinFor(descriptor, 0, 1, 50000, "02".repeat(32))];
        const destination = { kind: "descriptor", descriptor: target, startIndex: 4 };
        const plan = buildPlan(descriptor, groupCoins(coins, "separate"), destination, 1, new Map(), "standard");
        assert.deepStrictEqual(plan.map(t => t.address), [target.derive(0, 4).address, target.derive(0, 5).address]);
        assert.deepStrictEqual(plan.map(t => t.addressIndex), [4, 5]);
        assert.deepStrictEqual(linkageWarnings(plan, destination), []);
    });

    console.log(`\n${pass} wizard tests passed.`);
})();
