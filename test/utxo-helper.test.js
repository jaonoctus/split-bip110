const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { UTXOHelper } = require("../dist/helper/utxo-helper");

let failed = 0;

function check(cond, msg) {
    if (cond) {
        console.log(`PASS ${msg}`);
    } else {
        console.log(`FAIL ${msg}`);
        failed++;
    }
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "utxo-helper-test-"));
const A = "mAAAAAAAAAAAAAAAAAAAAA";
const B = "mBBBBBBBBBBBBBBBBBBBBB";
const C = "2CCCCCCCCCCCCCCCCCCCCCC";
const D = "2DDDDDDDDDDDDDDDDDDDDDD";
const txid = (n) => n.toString(16).padStart(64, "0");

function fillLine(txidHex, vout, address, value, label = "") {
    return `2026-08-01 23:05:56,${txidHex}:${vout},${address},${label},${value}`;
}

const lines = [];
lines.push("Date (UTC),Output,Address,Label,Value");
lines.push(fillLine(txid(1), 0, A, "0.00045459"));
lines.push(fillLine(txid(10), 1, A, "0.00010000"));
lines.push(fillLine(txid(2), 0, B, "0.00333372"));
lines.push("[");
lines.push(fillLine(txid(3), 0, C, "0.00635848"));
lines.push(fillLine(txid(4), 1, D, "0.00343164"));
lines.push("]");

const goodFile = path.join(tmp, "good.csv");
fs.writeFileSync(goodFile, lines.join("\n"));

const utxos = new UTXOHelper(goodFile).parse();

check(utxos.length === 3, "three groups (reuse, singleton, brackets)");
check(utxos[0].length === 2, "address reuse consolidated into one group");
check(utxos[1].length === 1, "different address on line 4 is a separate singleton");
check(utxos[2].length === 2, "bracket group holds two utxos");
check(utxos[0][0].txid === txid(1) && utxos[0][0].vout === 0, "txid and vout parsed (0)");
check(utxos[0][1].vout === 1, "vout parsed (1)");
check(utxos[0][0].address === A, "address parsed");
check(utxos[0][0].amount === 45459, "BTC value converted to sats (0.00045459)");
check(utxos[2][0].amount === 635848, "BTC value converted to sats (0.00635848)");
check(utxos[2][1].amount === 343164, "BTC value converted to sats (0.00343164)");

function parseBad(content) {
    const file = path.join(tmp, `bad-${Math.random().toString(16).slice(2)}.csv`);
    fs.writeFileSync(file, content);
    const script = `const { UTXOHelper } = require(${JSON.stringify(require.resolve("../dist/helper/utxo-helper"))}); new UTXOHelper(${JSON.stringify(file)}).parse();`;
    return spawnSync(process.execPath, ["-e", script], { encoding: "utf8", cwd: path.join(__dirname, "..") });
}

let r = parseBad("a,b,c,0.0004");
check(r.status === 1 && r.stderr.includes("expected 5 comma-separated tokens (Date,Output,Address,Label,Value)"), "rejects <5 columns with format error");

r = parseBad(`x,${txid(1)}:0,${A},,３２２６６５０００`);
check(r.status === 1 && r.stderr.includes("contains non-ASCII character(s)"), "rejects full-width-digit value with non-ASCII hint");

r = parseBad(`x,${txid(1)}:0,${A},,0`);
check(r.status === 1 && r.stderr.includes("value must be greater than 0"), "rejects zero value");

r = parseBad(`x,not-a-prevout,${A},,0.00045459`);
check(r.status === 1 && r.stderr.includes('invalid output: "not-a-prevout"'), "rejects malformed output with per-field error");

fs.rmSync(tmp, { recursive: true, force: true });

if (failed > 0) {
    console.error(`${failed} check(s) failed`);
    process.exit(1);
}