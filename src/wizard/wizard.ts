import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";
import ora from "ora";
import base58 from "bs58check";
import { checkbox, confirm, input, number, password, select } from "@inquirer/prompts";
import { BIP32Interface } from "bip32";
import { address as btcAddress, networks } from "bitcoinjs-lib";
import { bip32 } from "../bip32";
import { ScriptType, ScriptTypeEnum } from "../script-type";
import { Backend, ElectrumBackend, EsploraBackend, assertChain } from "./backend";
import {
    Destination, GroupingMode, PlannedTx, buildPlan, describePlan, destinationAddress, groupCoins, linkageWarnings, verifyParent,
} from "./builder";
import { BIP110, BITCOIN, ChainProfile } from "./chain";
import { Descriptor, parseDescriptor, walletFingerprints } from "./descriptor";
import { matchKeys, mnemonicProblem, rootFromMnemonic, signPlan } from "./hot-signer";
import { Coin, ScanResult, findLatestScan, formatBtc, outpoint, scanDescriptor, writeScanFile } from "./scan";

// Answers given as command-line flags, per chain. Anything left undefined is asked.
export type ChainAnswers = {
    esplora?: string;
    electrum?: string;
    scan?: "refresh" | "full" | "offline";
    // "all", "moved" (Bitcoin step: the coins moved on BIP110) or comma-separated txid:vout.
    coins?: string;
    grouping?: GroupingMode;
    destAddress?: string;
    destXpub?: string;
    destType?: "segwit" | "taproot" | "p2sh" | "legacy";
    destDescriptor?: string;
    destIndex?: number;
    feeRate?: number;
    sign?: "psbt" | "hot";
};

export type WizardOptions = {
    descriptor?: string;
    // Accept the privacy notice, linkage warnings and confirmations without asking.
    yes: boolean;
    // Whether to run the Bitcoin step; asked when undefined.
    btc?: boolean;
    bip110: ChainAnswers;
    bitcoin: ChainAnswers;
    electrumSelfSigned?: boolean;
    gapLimit: number;
    scanDir: string;
    outputDir: string;
};

// `approved` records that the user accepted the privacy notice; nothing connects before that.
type BackendChoice = { open(): Promise<Backend>; label: string; approved?: boolean; verified?: boolean };

const warn = (text: string) => console.log(chalk.yellow(`⚠ ${text}`));
const danger = (text: string) => console.log(chalk.red.bold(text));
const info = (text: string) => console.log(chalk.cyan(text));
const fromFlag = (question: string, answer: string) => console.log(`${chalk.green("✔")} ${chalk.bold(question)} ${chalk.cyan(answer)} ${chalk.dim("(flag)")}`);

// Thrown for a bad flag value, so the message names the flag.
function flagError(flag: string, message: string): Error {
    return new Error(`${flag}: ${message}`);
}

function flagName(chain: ChainProfile, name: string): string {
    return chain === BIP110 ? `--${name}` : `--btc-${name}`;
}

async function confirmUnlessYes(options: WizardOptions, message: string, defaultValue = true): Promise<boolean> {
    if (options.yes) {
        fromFlag(message, "Yes");
        return true;
    }
    return confirm({ message, default: defaultValue });
}

function parseOrThrow(text: string, flag: string): Descriptor {
    try { return parseDescriptor(text); }
    catch (error) { throw flagError(flag, error instanceof Error ? error.message : String(error)); }
}

function describeDescriptor(descriptor: Descriptor): string {
    const kinds: Record<Descriptor["kind"], string> = {
        "pkh": "Legacy (P2PKH)",
        "sh-wpkh": "Nested SegWit (P2SH-P2WPKH)",
        "wpkh": "Native SegWit (P2WPKH)",
        "tr": "Taproot (P2TR)",
        "wsh-sortedmulti": `Multisig ${descriptor.threshold}-of-${descriptor.keys.length} (P2WSH)`,
    };
    const keys = descriptor.keys.map(k => `[${k.fingerprint.toString("hex")}${k.hasOrigin ? k.originPath.slice(1) : ""}]`).join(" ");
    return `${kinds[descriptor.kind]}, keys ${keys}, ${descriptor.branches} branch(es)`;
}

async function askDescriptor(message = "Paste the output descriptor of the wallet holding the coins:", preset?: { text: string; flag: string }): Promise<Descriptor> {
    let descriptor: Descriptor;
    if (preset) {
        descriptor = parseOrThrow(preset.text, preset.flag);
        fromFlag(message, descriptor.text);
    } else {
        const text = await input({
            message,
            validate: value => {
                try { parseDescriptor(value); return true; }
                catch (error) { return error instanceof Error ? error.message : String(error); }
            },
        });
        descriptor = parseDescriptor(text);
    }
    info(`  ${describeDescriptor(descriptor)}`);
    info(`  First address: ${descriptor.derive(0, 0).address}`);
    if (descriptor.addedChange) info("  Receive-only descriptor: the matching /1/* change branch will be scanned too.");
    return descriptor;
}

async function askBackend(chain: ChainProfile, options: WizardOptions, answers: ChainAnswers): Promise<BackendChoice> {
    // Every connection is checked to be on the right chain before it is used.
    const verified = (label: string, connect: () => Promise<Backend>): BackendChoice => {
        const choice: BackendChoice = {
            label,
            open: async () => {
                const backend = await connect();
                if (!choice.verified) {
                    try { await assertChain(backend, chain); }
                    catch (error) { backend.close(); throw error; }
                    choice.verified = true;
                }
                return backend;
            },
        };
        return choice;
    };
    const esplora = (url: string): BackendChoice => {
        new EsploraBackend(url); // validate the URL up front
        return verified(url, async () => new EsploraBackend(url));
    };
    const electrum = (url: string): BackendChoice =>
        verified(url, () => ElectrumBackend.connect(url, { allowSelfSigned: options.electrumSelfSigned }));

    if (answers.esplora) return esplora(answers.esplora);
    if (answers.electrum) return electrum(answers.electrum);

    const kind = await select({
        message: `Where should the ${chain.name} chain be read from?`,
        choices: [
            { name: `${chain.defaultEsploraName} (${chain.defaultEsplora})`, value: "default" },
            { name: `${chain.defaultElectrumName} (${chain.defaultElectrum})`, value: "default-electrum" },
            { name: `Another Electrum server on the ${chain.name} chain`, value: "electrum" },
            { name: `Another Esplora API on the ${chain.name} chain`, value: "esplora" },
        ],
    });
    if (kind === "default") return esplora(chain.defaultEsplora);
    if (kind === "default-electrum") return electrum(chain.defaultElectrum);
    if (kind === "esplora") {
        const url = await input({
            message: "Esplora API base URL:",
            validate: value => { try { new EsploraBackend(value); return true; } catch (e) { return (e as Error).message; } },
        });
        return esplora(url.trim());
    }
    const url = await input({
        message: "Electrum server (ssl://host:50002 or tcp://host:50001):",
        validate: value => /^(?:(ssl|tls|tcp):\/\/)?[^:/\s]+:\d{1,5}$/.test(value.trim()) || "Use ssl://host:port or tcp://host:port",
    });
    return electrum(url.trim());
}

async function confirmConnectionPrivacy(options: WizardOptions, backend: BackendChoice, action = "Connect and scan?"): Promise<void> {
    if (backend.approved) return;
    console.log();
    warn(chalk.bold("Privacy notice"));
    warn(`This asks ${backend.label} about your addresses (or their transactions), one at a time.`);
    warn("Your descriptor and xpub never leave this machine, but the server operator sees your IP address");
    warn("and every address queried, and can link them together as one wallet, on both chains.");
    warn("Use your own server, a VPN or Tor to reduce what the operator learns.");
    const ok = await confirmUnlessYes(options, action);
    if (!ok) throw new Error("Aborted before connecting");
    backend.approved = true;
}

async function obtainCoins(chain: ChainProfile, descriptor: Descriptor, backend: BackendChoice, options: WizardOptions, answers: ChainAnswers): Promise<Coin[]> {
    const { scan: saved, errors } = findLatestScan(options.scanDir, chain, descriptor);
    for (const error of errors) warn(`Ignoring unreadable scan file: ${error}`);

    let previous: ScanResult | undefined;
    if (saved) {
        const total = saved.coins.reduce((s, c) => s + c.value, 0);
        info(`Found a saved ${chain.name} scan from ${saved.scannedAt} (${saved.coins.length} coins, ${formatBtc(total)} BTC):`);
        info(`  ${path.relative(process.cwd(), saved.file)}`);
        const question = "How do you want to use it?";
        const mode = answers.scan ? (fromFlag(question, answers.scan), answers.scan) : await select({
            message: question,
            choices: [
                {
                    name: "Quick refresh",
                    value: "refresh",
                    description: "Re-check known coins and only scan addresses after the last used one. Misses new coins on older addresses.",
                },
                { name: "Full rescan", value: "full", description: "Scan every address again from index 0." },
                { name: "Use saved coins without connecting", value: "offline", description: "No network access. Coins may already be spent." },
            ],
        });
        if (mode === "offline") return saved.coins;
        if (mode === "refresh") previous = saved;
    } else if (answers.scan === "offline") {
        throw flagError(flagName(chain, "scan"), `no saved ${chain.name} scan of this descriptor in ${options.scanDir}`);
    }

    await confirmConnectionPrivacy(options, backend);
    const spinner = ora(`Connecting to ${backend.label}`).start();
    let result: ScanResult;
    let client: Backend | undefined;
    try {
        client = await backend.open();
        result = await scanDescriptor(descriptor, client, {
            gapLimit: options.gapLimit,
            onProgress: message => { spinner.text = message; },
        }, previous);
        spinner.succeed(`Checked ${result.addressesChecked} addresses, found ${result.coins.length} coin(s)`);
    } catch (error) {
        spinner.fail("Scan failed");
        throw error;
    } finally {
        client?.close();
    }
    // The saved scan only speeds up the next run, so failing to write it must not lose this one.
    try {
        const file = writeScanFile(options.scanDir, chain, descriptor, backend.label, result);
        info(`Saved scan to ${path.relative(process.cwd(), file)} (delete it whenever you like)`);
    } catch (error) {
        warn(`Could not save the scan to ${path.resolve(options.scanDir)} (${(error as NodeJS.ErrnoException).code ?? error}); continuing without it.`);
    }
    return result.coins;
}

// `preselected` holds outpoints moved on BIP110, so the Bitcoin step starts with the same coins.
async function selectCoins(
    chain: ChainProfile, coins: Coin[], step: (branch: number) => string, answers: ChainAnswers, preselected?: Set<string>,
): Promise<Coin[]> {
    if (answers.coins) {
        const flag = flagName(chain, "coins");
        let chosen: Coin[];
        if (answers.coins === "all") {
            chosen = coins;
        } else if (answers.coins === "moved") {
            if (!preselected) throw flagError(flag, `"moved" only applies to the Bitcoin step`);
            chosen = coins.filter(c => preselected.has(outpoint(c)));
        } else {
            const byOutpoint = new Map(coins.map(c => [outpoint(c), c]));
            chosen = answers.coins.split(",").map(item => item.trim()).filter(Boolean).map(item => {
                const coin = byOutpoint.get(item);
                if (!coin) throw flagError(flag, `${item} is not one of this wallet's coins on ${chain.name}`);
                return coin;
            });
        }
        if (chosen.length === 0) throw flagError(flag, "selects no coins");
        const unique = [...new Set(chosen)];
        fromFlag("Coins:", coinSummary(unique));
        printCoins(unique, step);
        return unique;
    }
    const width = Math.max(...coins.map(c => formatBtc(c.value).length));
    const selected = await checkbox({
        message: `Select the coins to ${chain === BIP110 ? "split" : "move"} (space toggles, a selects all, enter confirms):`,
        pageSize: 15,
        loop: false,
        required: true,
        // Once answered, collapse to a summary; the coins are listed one per line below it.
        theme: { style: { renderSelectedChoices: (choices: ReadonlyArray<{ value: Coin }>) => coinSummary(choices.map(c => c.value)) } },
        choices: coins.map(c => ({
            value: c,
            // Never shortened: the full txid:vout identifies the coin.
            name: `${formatBtc(c.value).padStart(width)} BTC  ${c.address}  /${step(c.branch)}/${c.index}  ${outpoint(c)}` +
                (c.confirmed ? "" : chalk.yellow("  unconfirmed")) +
                (preselected?.has(outpoint(c)) ? chalk.green("  moved on BIP110") : ""),
            checked: preselected?.has(outpoint(c)) ?? false,
        })),
    });
    printCoins(selected, step);
    return selected;
}

function coinSummary(coins: Coin[]): string {
    return `${coins.length} coin(s), ${formatBtc(coins.reduce((s, c) => s + c.value, 0))} BTC`;
}

// Keeps the selection visible in the terminal history after the prompt closes.
function printCoins(coins: Coin[], step: (branch: number) => string): void {
    const width = Math.max(...coins.map(c => formatBtc(c.value).length));
    for (const c of coins) {
        console.log(chalk.dim("  ") + `${formatBtc(c.value).padStart(width)} BTC  ${c.address}  /${step(c.branch)}/${c.index}  ` +
            chalk.dim(outpoint(c)) + (c.confirmed ? "" : chalk.yellow("  unconfirmed")));
    }
}

function toXpub(value: string): string {
    if (value.startsWith("xpub")) return value;
    const data = Buffer.from(base58.decode(value));
    data.writeUInt32BE(networks.bitcoin.bip32.public, 0);
    return base58.encode(data);
}

const DEST_TYPES = {
    segwit: ScriptType.P2WPKH,
    taproot: ScriptType.P2TR,
    p2sh: ScriptType.P2SH,
    legacy: ScriptType.P2PKH,
};

// Destination from flags; undefined when no destination flag was given.
function destinationFromFlags(chain: ChainProfile, source: Descriptor, answers: ChainAnswers): Destination | undefined {
    const index = answers.destIndex ?? 0;
    if (answers.destAddress) {
        try { btcAddress.toOutputScript(answers.destAddress, networks.bitcoin); }
        catch { throw flagError(flagName(chain, "dest-address"), "not a valid mainnet address"); }
        return { kind: "address", address: answers.destAddress };
    }
    if (answers.destXpub) {
        const flag = flagName(chain, "dest-xpub");
        let account: BIP32Interface;
        try { account = bip32.fromBase58(toXpub(answers.destXpub), networks.bitcoin); }
        catch { throw flagError(flag, "not a valid mainnet extended public key"); }
        const inferred = answers.destXpub.startsWith("zpub") ? ScriptType.P2WPKH : answers.destXpub.startsWith("ypub") ? ScriptType.P2SH : undefined;
        const scriptType = answers.destType ? DEST_TYPES[answers.destType] : inferred;
        if (!scriptType) throw flagError(flagName(chain, "dest-type"), `required with an xpub (${Object.keys(DEST_TYPES).join(", ")})`);
        return { kind: "xpub", account, scriptType, startIndex: index };
    }
    if (answers.destDescriptor) {
        const descriptor = parseOrThrow(answers.destDescriptor, flagName(chain, "dest-descriptor"));
        if (descriptor.id === source.id) throw flagError(flagName(chain, "dest-descriptor"), "is the wallet the coins are already in");
        return { kind: "descriptor", descriptor, startIndex: index };
    }
    return undefined;
}

async function askDestination(chain: ChainProfile, source: Descriptor, options: WizardOptions, answers: ChainAnswers): Promise<Destination> {
    const preset = destinationFromFlags(chain, source, answers);
    if (preset) {
        const first = destinationAddress(preset, 0);
        fromFlag(`Where should the coins go on ${chain.name}?`, first.index === undefined ? first.address : `${first.address} (address #${first.index}, then the next ones)`);
        if (preset.kind !== "address" && !await confirmUnlessYes(options, "Does your destination wallet show this address?")) {
            throw new Error("Destination wallet not confirmed; check the destination flags");
        }
        return preset;
    }
    const kind = await select({
        message: `Where should the coins go on ${chain.name}?`,
        choices: [
            { name: "A new wallet (xpub): a fresh address for every transaction", value: "xpub" },
            { name: "A new wallet (output descriptor): a fresh address for every transaction", value: "descriptor" },
            { name: "A single address (e.g. an exchange deposit)", value: "address" },
        ],
    });
    if (kind === "descriptor") {
        const descriptor = await askDescriptor("Output descriptor of the destination wallet:");
        if (descriptor.id === source.id) {
            warn("That is the wallet the coins are already in. Use a new wallet.");
            return askDestination(chain, source, options, answers);
        }
        const startIndex = await number({ message: "First receive index to use:", default: 0, min: 0, required: true });
        const destination: Destination = { kind: "descriptor", descriptor, startIndex: startIndex! };
        info(`  First destination address: ${destinationAddress(destination, 0).address}`);
        info("  Check that your destination wallet shows this same address.");
        if (!await confirm({ message: "Is that the right wallet?", default: true })) return askDestination(chain, source, options, answers);
        return destination;
    }
    if (kind === "address") {
        const address = await input({
            message: "Destination address:",
            validate: value => {
                try { btcAddress.toOutputScript(value.trim(), networks.bitcoin); return true; }
                catch { return "Not a valid mainnet address"; }
            },
        });
        return { kind: "address", address: address.trim() };
    }

    const encoded = (await input({
        message: "Account xpub/ypub/zpub of the destination wallet:",
        validate: value => {
            try { bip32.fromBase58(toXpub(value.trim()), networks.bitcoin); return true; }
            catch { return "Not a valid mainnet extended public key"; }
        },
    })).trim();
    const account: BIP32Interface = bip32.fromBase58(toXpub(encoded), networks.bitcoin);
    const inferred = encoded.startsWith("zpub") ? ScriptType.P2WPKH : encoded.startsWith("ypub") ? ScriptType.P2SH : undefined;
    const scriptType = inferred ?? await select({
        message: "Address type of the destination wallet:",
        choices: [
            { name: "Native SegWit (bc1q...)", value: ScriptType.P2WPKH },
            { name: "Taproot (bc1p...)", value: ScriptType.P2TR },
            { name: "Nested SegWit (3...)", value: ScriptType.P2SH },
            { name: "Legacy (1...)", value: ScriptType.P2PKH },
        ],
    });
    const startIndex = await number({ message: "First receive index to use:", default: 0, min: 0, required: true });
    const destination: Destination = { kind: "xpub", account, scriptType, startIndex: startIndex! };
    info(`  First destination address: ${destinationAddress(destination, 0).address}`);
    info("  Check that your destination wallet shows this same address.");
    if (!await confirm({ message: "Is that the right wallet?", default: true })) return askDestination(chain, source, options, answers);
    return destination;
}

async function fetchParents(options: WizardOptions, descriptor: Descriptor, coins: Coin[], backend: BackendChoice): Promise<Map<string, Buffer>> {
    const parents = new Map<string, Buffer>();
    if (descriptor.scriptType.typeEnum !== ScriptTypeEnum.P2PKH) return parents;
    info("Legacy coins need their parent transactions downloaded to check their values.");
    await confirmConnectionPrivacy(options, backend, "Connect to download them?");
    const spinner = ora("Fetching parent transactions of legacy coins").start();
    const client = await backend.open();
    try {
        for (const coin of coins) {
            const raw = parents.get(coin.txid)?.toString("hex") ?? await client.getRawTransaction(coin.txid);
            parents.set(coin.txid, verifyParent(coin, raw, descriptor.derive(coin.branch, coin.index).output));
        }
        spinner.succeed("Verified parent transactions of legacy coins");
    } catch (error) {
        spinner.fail();
        throw error;
    } finally {
        client.close();
    }
    return parents;
}

async function recommendedFee(backend: BackendChoice): Promise<number | undefined> {
    try {
        const client = await backend.open();
        try { return await client.recommendedFeeRate(); } finally { client.close(); }
    } catch {
        return undefined;
    }
}

async function planTransactions(
    chain: ChainProfile, descriptor: Descriptor, coins: Coin[], backend: BackendChoice, options: WizardOptions, answers: ChainAnswers,
    preselected?: Set<string>,
): Promise<{ plan: PlannedTx[]; feeRate: number; destination: Destination }> {
    const selected = await selectCoins(chain, coins, b => descriptor.branchStep(b), answers, preselected);
    const distinctAddresses = new Set(selected.map(c => c.address)).size;

    let grouping: GroupingMode = "separate";
    if (distinctAddresses > 1 && answers.grouping) {
        grouping = answers.grouping;
        fromFlag("How should the selected coins be sent?", grouping === "separate" ? "One transaction per coin" : "Consolidate into one transaction");
    } else if (distinctAddresses > 1) {
        grouping = await select({
            message: "How should the selected coins be sent?",
            choices: [
                { name: "One transaction per coin (recommended)", value: "separate" as const, description: "Coins sharing an address are kept together, as they are already linked." },
                { name: "Consolidate into one transaction", value: "consolidate" as const, description: "Cheaper, but publicly links all the selected coins." },
            ],
        });
    }

    const destination = await askDestination(chain, descriptor, options, answers);
    const groups = groupCoins(selected, grouping);
    // Only suggest a fee when the user already agreed to connect (not in offline mode).
    const fallback = backend.approved && answers.feeRate === undefined ? await recommendedFee(backend) : undefined;
    if (answers.feeRate !== undefined) fromFlag("Fee rate (sat/vB):", String(answers.feeRate));
    const feeRate = answers.feeRate ?? await number({
        message: "Fee rate (sat/vB):",
        default: fallback ?? 1,
        min: 1,
        step: "any",
        required: true,
    });
    const parents = await fetchParents(options, descriptor, selected, backend);
    let plan: PlannedTx[];
    try {
        plan = buildPlan(descriptor, groups, destination, feeRate!, parents, chain.sighash);
    } catch (error) {
        warn(error instanceof Error ? error.message : String(error));
        throw new RetryPlan();
    }

    const warnings = linkageWarnings(plan, destination);
    if (warnings.length > 0) {
        console.log();
        warn(chalk.bold(`Privacy warning: these coins would be linked on the ${chain.name} chain`));
        for (const w of warnings) warn(w);
        if (chain === BIP110) {
            warn("These coins also exist on BTC, so a link made here tells anyone watching both chains that");
            warn("they belong to the same owner, even if you never linked them on BTC.");
            warn("If you link them anyway, consider coinjoining the same coins on BTC with");
            warn("https://wasabiwallet.io so the link made here does not carry over to your BTC.");
        } else {
            warn("Anyone watching Bitcoin will see that these coins belong to the same owner.");
            warn("To move them without linking, consider coinjoining with https://wasabiwallet.io instead.");
        }
        if (!await confirmUnlessYes(options, "Link them anyway?", false)) {
            throw new RetryPlan();
        }
    }
    return { plan, feeRate: feeRate!, destination };
}

class RetryPlan extends Error {}

function createOutputDir(chain: ChainProfile, options: WizardOptions, descriptor: Descriptor): string {
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
    for (let attempt = 0; attempt < 100; attempt++) {
        const dir = path.join(options.outputDir, `${chain.outputPrefix}_${descriptor.id}_${stamp}${attempt ? `-${attempt}` : ""}`);
        try {
            fs.mkdirSync(dir, { recursive: false, mode: 0o700 });
            return dir;
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
    }
    throw new Error("Could not create an output directory");
}

// Prints each PSBT or transaction so it stays in the terminal history, not only in the output files.
function printResults(kind: string, items: string[], label: (i: number) => string): void {
    items.forEach((item, i) => {
        console.log();
        console.log(chalk.bold(`${kind} ${i + 1} of ${items.length}`) + chalk.dim(` (${label(i)})`));
        console.log(item);
    });
    console.log();
}

function writeNew(file: string, content: string | Buffer): void {
    fs.writeFileSync(file, content, { flag: "wx", mode: 0o600 });
}

async function exportPsbts(chain: ChainProfile, plan: PlannedTx[], report: string, makeDir: () => string): Promise<void> {
    const dir = makeDir();
    plan.forEach((tx, i) => writeNew(path.join(dir, `tx-${String(i + 1).padStart(3, "0")}.psbt`), tx.psbt.toBuffer()));
    writeNew(path.join(dir, "unsigned-psbts.txt"), plan.map(tx => tx.psbt.toBase64()).join("\n") + "\n");
    writeNew(path.join(dir, "tx-report.txt"), report + "\n");
    info(`Wrote ${plan.length} unsigned PSBT(s) to ${dir}`);
    printResults("Unsigned PSBT (base64)", plan.map(tx => tx.psbt.toBase64()), i => `tx-${String(i + 1).padStart(3, "0")}.psbt`);
    if (chain.sighash === "unified") {
        warn("Each input asks for sighash type 0x21 (SIGHASH_ALL|SIGHASH_UNIFIED). Only a BIP110-aware signer");
        warn("can produce these signatures; regular wallets and hardware wallets will refuse or sign for BTC instead.");
    } else {
        info("These are standard PSBTs: sign them with Sparrow, a hardware wallet or any PSBT-capable wallet.");
    }
}

async function signHot(chain: ChainProfile, descriptor: Descriptor, plan: PlannedTx[], report: string, makeDir: () => string): Promise<void> {
    console.log();
    danger("DANGER: hot wallet signing");
    danger("Your seed words are about to be typed into this computer. Any malware on it can steal");
    danger("every coin these words control, on both chains. Prefer the PSBT option on an offline signer.");
    danger("Seed words and passphrases are kept in memory only and never written to disk.");
    if (!await confirm({ message: "I understand the risk. Continue?", default: false })) throw new RetryPlan();

    const signers = new Map<number, BIP32Interface>();
    while (signers.size < descriptor.threshold) {
        const label = descriptor.threshold > 1 ? ` (${signers.size + 1} of ${descriptor.threshold})` : "";
        const words = await password({
            message: `Seed words${label}:`,
            mask: "*",
            validate: value => mnemonicProblem(value) ?? true,
        });
        const passphrase = await password({ message: "BIP39 passphrase (leave empty if none):", mask: "*" });
        const root = rootFromMnemonic(words, passphrase);
        const matched = matchKeys(descriptor, root).filter(k => !signers.has(k));
        if (matched.length === 0) {
            warn(`Seed with fingerprint ${root.fingerprint.toString("hex")} does not match any unused key in the descriptor.`);
            warn("A wrong or missing passphrase produces a different fingerprint.");
            if (!await confirm({ message: "Try again?", default: true })) throw new Error("Aborted: no matching seed");
            continue;
        }
        for (const k of matched) {
            if (signers.size < descriptor.threshold) signers.set(k, root);
        }
        info(`  Matched key [${root.fingerprint.toString("hex")}]`);
    }

    let transactions;
    try {
        transactions = signPlan(descriptor, plan, signers, chain.sighash);
    } finally {
        signers.clear();
    }
    const dir = makeDir();
    writeNew(path.join(dir, "raw-txs.txt"), transactions.map(tx => tx.toHex()).join("\n") + "\n");
    writeNew(path.join(dir, "tx-report.txt"), report + "\n");
    info(`Wrote ${transactions.length} signed transaction(s) to ${path.join(dir, "raw-txs.txt")}`);
    printResults("Signed transaction (hex)", transactions.map(tx => tx.toHex()), i => `txid ${transactions[i].getId()}`);
    if (chain === BIP110) {
        info(`Nothing was broadcast. Check each transaction, e.g. paste it into ${BIP110.explorerTx}`);
        info(`(it should be valid there and invalid on ${BITCOIN.explorerTx}), then broadcast it.`);
    } else {
        info(`Nothing was broadcast. Check each transaction, e.g. paste it into ${BITCOIN.explorerTx}, then broadcast it.`);
    }
}

// Scans, selects, plans and signs on one chain. Returns the outpoints that were moved.
async function runChain(chain: ChainProfile, descriptor: Descriptor, options: WizardOptions, preselected?: Set<string>): Promise<Set<string>> {
    let answers = chain === BIP110 ? options.bip110 : options.bitcoin;
    const backend = await askBackend(chain, options, answers);
    const coins = await obtainCoins(chain, descriptor, backend, options, answers);
    if (coins.length === 0) {
        warn(`No coins found for this descriptor on the ${chain.name} chain.`);
        return new Set();
    }
    const total = coins.reduce((s, c) => s + c.value, 0);
    info(`${coins.length} coin(s), ${formatBtc(total)} BTC in total on ${chain.name} (wallet ${walletFingerprints(descriptor)})\n`);
    if (preselected) {
        const found = coins.filter(c => preselected.has(outpoint(c))).length;
        info(`${found} of the ${preselected.size} coin(s) you moved on BIP110 still exist on Bitcoin and are preselected.\n`);
    }

    for (;;) {
        try {
            const { plan, feeRate } = await planTransactions(chain, descriptor, coins, backend, options, answers, preselected);
            const report = describePlan(plan, feeRate);
            console.log("\n" + report + "\n");
            if (!await confirmUnlessYes(options, "Create these transactions?")) throw new RetryPlan();

            const canSignHot = descriptor.keys.every(k => k.hasOrigin);
            if (answers.sign === "hot" && !canSignHot) {
                throw flagError(flagName(chain, "sign"), "hot signing needs key origins ([fingerprint/path]) in the descriptor");
            }
            if (answers.sign) fromFlag("How do you want to sign?", answers.sign === "psbt" ? "Export unsigned PSBTs" : "Type seed words + passphrase here");
            const method = answers.sign ?? await select({
                message: "How do you want to sign?",
                choices: [
                    { name: "Export unsigned PSBTs (recommended)", value: "psbt" },
                    {
                        name: chalk.red("Type seed words + passphrase here (hot wallet, dangerous)"),
                        value: "hot",
                        disabled: canSignHot ? false : "(descriptor has no key origin [fingerprint/path])",
                    },
                ],
            });
            const makeDir = () => createOutputDir(chain, options, descriptor);
            if (method === "psbt") await exportPsbts(chain, plan, report, makeDir);
            else await signHot(chain, descriptor, plan, report, makeDir);
            return new Set(plan.flatMap(tx => tx.coins.map(outpoint)));
        } catch (error) {
            if (!(error instanceof RetryPlan)) throw error;
            // Flag answers led here, so ask from now on instead of retrying the same answers.
            answers = { esplora: answers.esplora, electrum: answers.electrum, scan: answers.scan };
            info("Okay, let's go back to coin selection.\n");
        }
    }
}

// In a container, a working directory on the same filesystem as / is not a mounted volume,
// so everything written there disappears with the container.
function warnIfOutputIsEphemeral(options: WizardOptions): void {
    if (!fs.existsSync("/.dockerenv")) return;
    try {
        const root = fs.statSync("/").dev;
        const dirs = [...new Set([path.resolve(options.scanDir), path.resolve(options.outputDir)])];
        if (dirs.some(dir => fs.statSync(dir).dev === root)) {
            warn(chalk.bold("Nothing is mounted for the output: the PSBTs, transactions and scan files this run"));
            warn(chalk.bold("writes will be lost when the container exits. To keep them, run it with"));
            warn(chalk.bold(`-v "$PWD:/data" --user "$(id -u):$(id -g)"`));
        }
    } catch {
        // Only a hint; never block the run on it.
    }
}

export async function runWizard(options: WizardOptions): Promise<void> {
    console.log(chalk.bold("\nsplit-bip110: move your coins on the BIP110 chain without replaying them on BTC\n"));
    warnIfOutputIsEphemeral(options);
    const descriptor = await askDescriptor(undefined, options.descriptor ? { text: options.descriptor, flag: "--descriptor" } : undefined);
    const moved = await runChain(BIP110, descriptor, options);

    console.log();
    const question = "Also check whether the same coins exist on Bitcoin (BTC) and move them to a new wallet?";
    if (options.btc !== undefined) fromFlag(question, options.btc ? "Yes" : "No");
    const again = options.btc ?? await confirm({ message: question, default: false });
    if (!again) return;
    console.log();
    warn(chalk.bold("Replay warning"));
    warn("BTC transactions are signed the normal way, and a normal transaction may also be valid on the");
    warn("BIP110 chain while the same coins are still unspent there. Broadcast your BIP110 split transactions");
    warn("and wait for them to confirm before broadcasting these, or the BTC transactions could be replayed");
    warn("on BIP110 and move those coins too.");
    console.log();
    await runChain(BITCOIN, descriptor, options, moved);
}
