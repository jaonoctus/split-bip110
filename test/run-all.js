const { spawnSync } = require("child_process");
const path = require("path");

const tests = [
    { file: "unified-sighash.test.js", args: ["unified_sighash_all.json"] },
    { file: "smoke-sign.test.js", args: [] },
    { file: "utxo-helper.test.js", args: [] },
];

for (const t of tests) {
    const res = spawnSync(process.execPath, [path.join(__dirname, t.file), ...t.args], { cwd: __dirname });
    process.stdout.write(res.stdout ?? "");
    process.stderr.write(res.stderr ?? "");
    if (res.status !== 0) {
        console.error(`\nFAIL ${t.file} (exit ${res.status})`);
        process.exit(1);
    }
}

console.log("\nAll test files passed.");