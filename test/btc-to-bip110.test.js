const assert = require("assert");
const { Transaction } = require("bitcoinjs-lib");
const { traceMissingParents, checkTarget, parseTargets, combinedSendOrder, CopyImpossibleError } = require("../dist/btc-to-bip110");
const { EsploraBackend } = require("../dist/wizard/backend");

function makeTx(inputs, outputs = 1) {
    const tx = new Transaction();
    tx.version = 2;
    for (const input of inputs) tx.addInput(Buffer.from(input.txid, "hex").reverse(), input.vout);
    for (let i = 0; i < outputs; i++) tx.addOutput(Buffer.from("51", "hex"), 1000);
    return tx;
}

async function run() {
    // Esplora fork lookups: a 404 means absent, anything else must name the txid.
    const unknown = "f".repeat(64);
    const missingFetch = async () => new Response("Transaction not found", { status: 404 });
    assert.strictEqual(await new EsploraBackend("https://mempool.guide/api", missingFetch).hasTransaction(unknown), false);
    const presentFetch = async () => new Response(JSON.stringify({ txid: unknown }), { status: 200 });
    assert.strictEqual(await new EsploraBackend("https://mempool.guide/api", presentFetch).hasTransaction(unknown), true);
    const outspendFetch = async () => new Response(JSON.stringify({ spent: true, txid: unknown, vin: 2, status: { confirmed: true } }), { status: 200 });
    assert.deepStrictEqual(await new EsploraBackend("https://mempool.guide/api", outspendFetch).outspend(unknown, 0),
        { spent: true, txid: unknown, vin: 2, confirmed: true });

    const shared = "a".repeat(64);
    const A = shared.toUpperCase();
    assert.deepStrictEqual(parseTargets([`${A}:1,${shared}:1`, shared]), [{ txid: shared, vout: 1 }, { txid: shared, vout: undefined }]);
    assert.throws(() => parseTargets(["abc"]), /Not a txid/);
    assert.throws(() => parseTargets([`${shared}:4294967296`]), /Not a txid/);
    assert.throws(() => parseTargets([" "]), /at least one/);

    // Shared ancestor: fetched once, ordered parents first.
    const a = makeTx([{ txid: shared, vout: 0 }]);
    const b = makeTx([{ txid: a.getId(), vout: 0 }]);
    const root = makeTx([{ txid: a.getId(), vout: 0 }, { txid: b.getId(), vout: 0 }]);
    const raws = new Map([a, b, root].map(tx => [tx.getId(), tx.toHex()]));
    const requested = [];
    const sources = {
        forkHas: async txid => txid === shared,
        getBitcoinRaw: async txid => { requested.push(txid); return raws.get(txid); },
        getForkOutspend: async () => ({ spent: false }),
    };
    const result = await traceMissingParents(root.getId(), sources, { concurrency: 2 });
    assert.deepStrictEqual(result.missing.map(tx => tx.txid), [a.getId(), b.getId(), root.getId()]);
    assert.deepStrictEqual(result.alreadyOnFork, [shared]);
    assert.strictEqual(requested.length, 3);
    assert.strictEqual(result.checked, 4);

    // A different fork spender blocks the copy.
    await assert.rejects(traceMissingParents(root.getId(), {
        ...sources, getForkOutspend: async () => ({ spent: true, txid: unknown, vin: 4, confirmed: true }),
    }), error => error instanceof CopyImpossibleError && error.blocker.kind === "spent-input" &&
        error.message.includes(`https://mempool.space/tx/${a.getId()}`) &&
        error.message.includes(`https://mempool.guide/tx/${shared}#vout=0`) &&
        error.message.includes(`https://mempool.guide/tx/${unknown}#vin=4`) &&
        error.blocker.spendingTx === a.getId() && error.blocker.input.txid === shared &&
        error.blocker.spentBy === unknown && error.blocker.confirmed === true);

    // The same spender on the fork means that branch was already copied.
    const sameSpender = makeTx([{ txid: shared, vout: 0 }]);
    const afterSameSpender = makeTx([{ txid: sameSpender.getId(), vout: 0 }]);
    const descendant = makeTx([{ txid: afterSameSpender.getId(), vout: 0 }]);
    const branchRaws = new Map([sameSpender, afterSameSpender, descendant].map(tx => [tx.getId(), tx.toHex()]));
    let ancestorLookups = 0;
    const partlyCopied = await traceMissingParents(descendant.getId(), {
        forkHas: async txid => txid === shared || (txid === sameSpender.getId() && ++ancestorLookups > 1),
        getBitcoinRaw: async txid => branchRaws.get(txid),
        getForkOutspend: async txid => txid === shared ? { spent: true, txid: sameSpender.getId(), confirmed: true } : { spent: false },
    });
    assert.deepStrictEqual(partlyCopied.missing.map(tx => tx.txid), [afterSameSpender.getId(), descendant.getId()]);
    assert(partlyCopied.alreadyOnFork.includes(sameSpender.getId()));

    await assert.rejects(traceMissingParents(sameSpender.getId(), {
        forkHas: async txid => txid === shared,
        getBitcoinRaw: async () => sameSpender.toHex(),
        getForkOutspend: async () => ({ spent: true, txid: sameSpender.getId() }),
    }), error => !(error instanceof CopyImpossibleError) && /cannot find that transaction/.test(error.message));

    // Coinbase mined after the split: never on the fork.
    const coinbase = makeTx([{ txid: "0".repeat(64), vout: 0xffffffff }]);
    const spendsCoinbase = makeTx([{ txid: coinbase.getId(), vout: 0 }]);
    const coinbaseRaws = new Map([coinbase, spendsCoinbase].map(tx => [tx.getId(), tx.toHex()]));
    await assert.rejects(traceMissingParents(spendsCoinbase.getId(), {
        forkHas: async () => false,
        getBitcoinRaw: async txid => coinbaseRaws.get(txid),
        getForkOutspend: async () => { throw new Error("unexpected outspend query"); },
    }), error => error instanceof CopyImpossibleError && error.blocker.kind === "missing-coinbase" && error.blocker.txid === coinbase.getId());

    await assert.rejects(traceMissingParents(root.getId(), { ...sources, getBitcoinRaw: async () => a.toHex() }), /wrong transaction/);
    await assert.rejects(traceMissingParents(root.getId(), sources, { maxTransactions: 2 }), /max-transactions/);

    // checkTarget verdicts.
    const onFork = await checkTarget({ txid: shared, vout: 3 }, { ...sources, getForkOutspend: async () => ({ spent: true, txid: unknown, vin: 1, confirmed: false }) });
    assert.deepStrictEqual(onFork, { status: "on-fork", target: { txid: shared, vout: 3 }, spentBy: unknown, spentByVin: 1, confirmed: false });
    assert.deepStrictEqual(await checkTarget({ txid: shared }, sources), { status: "on-fork", target: { txid: shared } });
    const copyable = await checkTarget({ txid: root.getId(), vout: 0 }, sources);
    assert.strictEqual(copyable.status, "copyable");
    const badVout = await checkTarget({ txid: root.getId(), vout: 1 }, sources);
    assert.strictEqual(badVout.status, "error");
    assert.match(badVout.message, /no output 1/);
    const blocked = await checkTarget({ txid: spendsCoinbase.getId() }, {
        forkHas: async () => false, getBitcoinRaw: async txid => coinbaseRaws.get(txid), getForkOutspend: async () => ({ spent: false }),
    });
    assert.strictEqual(blocked.status, "blocked");

    // Combined order keeps shared ancestors once and parents first.
    const other = await checkTarget({ txid: b.getId() }, sources);
    const order = combinedSendOrder([other, copyable, blocked]).map(tx => tx.txid);
    assert.deepStrictEqual(order, [a.getId(), b.getId(), root.getId()]);

    console.log("btc-to-bip110 tests passed");
}

run().catch(error => { console.error(error); process.exitCode = 1; });
