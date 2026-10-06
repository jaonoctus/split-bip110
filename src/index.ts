#!/usr/bin/env node
import chalk from "chalk";
import { Command, InvalidArgumentError, Option } from "commander";
import { runLegacy } from "./legacy";
import { ChainAnswers, runWizard } from "./wizard/wizard";
// Resolved at runtime from dist/, so package.json stays outside rootDir.
const { version } = require("../package.json") as { version: string };

function positiveInt(value: string): number {
    const n = Number(value);
    if (!Number.isSafeInteger(n) || n < 1) throw new InvalidArgumentError("Must be a positive integer.");
    return n;
}

const program = new Command()
    .name("split-bip110")
    .description("Split coins on the BIP110 chain from BTC, signing with SIGHASH_UNIFIED so they cannot be replayed")
    .version(version);

function nonNegativeInt(value: string): number {
    const n = Number(value);
    if (!Number.isSafeInteger(n) || n < 0) throw new InvalidArgumentError("Must be a non-negative integer.");
    return n;
}

function feeRate(value: string): number {
    const n = Number(value);
    if (!Number.isFinite(n) || n < 1) throw new InvalidArgumentError("Must be a number of at least 1 sat/vB.");
    return n;
}

// The same answer flags exist for both chains: unprefixed for BIP110, "--btc-" for the Bitcoin step.
function addChainOptions(command: Command, prefix: string, chain: string): void {
    const p = prefix ? `${prefix}-` : "";
    const dest = [`${p}dest-address`, `${p}dest-xpub`, `${p}dest-descriptor`];
    // Commander matches conflicts by attribute name (camelCase), not by flag spelling.
    const camel = (flag: string) => flag.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());
    const others = (name: string) => dest.filter(d => d !== name).map(camel);
    command
        .addOption(new Option(`--${p}esplora <url>`, `Esplora API of the ${chain} chain`).conflicts(camel(`${p}electrum`)))
        .addOption(new Option(`--${p}electrum <server>`, `Electrum server of the ${chain} chain, e.g. ssl://host:50002`))
        .addOption(new Option(`--${p}scan <mode>`, `what to do with a saved ${chain} scan`).choices(["refresh", "full", "offline"]))
        .addOption(new Option(`--${p}coins <list>`, `coins to move: "all"${prefix ? `, "moved" (those moved on BIP110)` : ""} or txid:vout,txid:vout`))
        .addOption(new Option(`--${p}grouping <mode>`, "one transaction per coin, or one for all").choices(["separate", "consolidate"]))
        .addOption(new Option(`--${p}dest-address <address>`, "send everything to this address").conflicts(others(`${p}dest-address`)))
        .addOption(new Option(`--${p}dest-xpub <xpub>`, "send to a new wallet's account xpub/ypub/zpub").conflicts(others(`${p}dest-xpub`)))
        .addOption(new Option(`--${p}dest-type <type>`, `address type for --${p}dest-xpub`).choices(["segwit", "taproot", "p2sh", "legacy"]))
        .addOption(new Option(`--${p}dest-descriptor <descriptor>`, "send to a new wallet's output descriptor").conflicts(others(`${p}dest-descriptor`)))
        .addOption(new Option(`--${p}dest-index <n>`, "first receive index of the destination wallet (default: 0)").argParser(nonNegativeInt))
        .addOption(new Option(`--${p}fee-rate <sat/vB>`, "fee rate").argParser(feeRate))
        .addOption(new Option(`--${p}sign <method>`, "psbt, or hot (seed words are still asked, never passed as flags)").choices(["psbt", "hot"]));
}

function chainAnswers(opts: Record<string, any>, prefix: "" | "btc"): ChainAnswers {
    const get = (name: string) => opts[prefix ? `${prefix}${name[0].toUpperCase()}${name.slice(1)}` : name];
    return {
        esplora: get("esplora"),
        electrum: get("electrum"),
        scan: get("scan"),
        coins: get("coins"),
        grouping: get("grouping"),
        destAddress: get("destAddress"),
        destXpub: get("destXpub"),
        destType: get("destType"),
        destDescriptor: get("destDescriptor"),
        destIndex: get("destIndex"),
        feeRate: get("feeRate"),
        sign: get("sign"),
    };
}

program
    .option("--descriptor <descriptor>", "output descriptor of the wallet holding the coins")
    .option("-y, --yes", "accept the privacy notice, privacy warnings and confirmations without asking (never the hot wallet warning)")
    .option("--btc", "also run the Bitcoin (BTC) step without asking")
    .option("--no-btc", "skip the Bitcoin (BTC) step without asking")
    .option("--electrum-self-signed", "accept self-signed TLS certificates from Electrum servers")
    .option("--gap-limit <n>", "consecutive unused addresses before a scan stops", positiveInt, 20)
    .option("--scan-dir <dir>", "where delete_later_*.csv scan files are read and written", ".")
    .option("--output-dir <dir>", "where the output folder with PSBTs or transactions is created", ".");
addChainOptions(program, "", "BIP110");
addChainOptions(program, "btc", "Bitcoin");
program
    .addHelpText("after", `
Every question can be answered with a flag; questions without a flag are still asked.
Seed words and passphrases are never accepted as flags.

Example (non-interactive BIP110 split to PSBTs, then stop):
  split-bip110 --descriptor "wpkh([fingerprint/84h/0h/0h]xpub.../<0;1>/*)" --scan full --coins all \\
    --grouping separate --dest-xpub zpub... --fee-rate 2 --sign psbt --no-btc --yes`)
    .action(async opts => {
        if (opts.destType && !opts.destXpub) program.error("--dest-type only applies to --dest-xpub.");
        if (opts.btcDestType && !opts.btcDestXpub) program.error("--btc-dest-type only applies to --btc-dest-xpub.");
        if (opts.coins === "moved") program.error(`--coins moved only applies to the Bitcoin step (--btc-coins moved).`);
        await runWizard({
            descriptor: opts.descriptor,
            yes: !!opts.yes,
            // Commander sets btc to true by default because of --no-btc; only explicit flags count.
            btc: program.getOptionValueSource("btc") === "cli" ? opts.btc : undefined,
            bip110: chainAnswers(opts, ""),
            bitcoin: chainAnswers(opts, "btc"),
            electrumSelfSigned: !!opts.electrumSelfSigned,
            gapLimit: opts.gapLimit,
            scanDir: opts.scanDir,
            outputDir: opts.outputDir,
        });
    });

program
    .command("legacy")
    .description("Original flow: read config.toml and a Sparrow UTXO CSV, sign with the seeds in the config")
    .option("-c, --config <file>", "config file", "config.toml")
    .action(opts => runLegacy(opts.config));

program.parseAsync().catch(error => {
    if (error instanceof Error && error.name === "ExitPromptError") {
        if (!process.stdin.isTTY) {
            console.error(chalk.red("\nA question above needs an answer, but no terminal is attached. Pass its flag (see --help)."));
            process.exit(1);
        }
        console.log(chalk.dim("\nCancelled."));
        process.exit(130);
    }
    console.error(chalk.red(`\n${error instanceof Error ? error.message : error}`));
    process.exit(1);
});
