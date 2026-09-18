import * as fs from "fs";
import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { BIP32Factory, BIP32Interface } from "bip32";
import { ConfigHelper } from "./helper/config-helper";
import { TransactionHelper } from "./helper/transaction-helper";
import { UTXOPrivkeyHelper } from "./helper/utxo-privkey-helper";
import { MnemonicsHelper } from "./helper/mnemonics-helper";
import { Report } from "./model/report";

export const bip32 = BIP32Factory(ecc);
bitcoin.initEccLib(ecc);

async function main() {
    console.log("Reading config info... ");
    const cfgHelper = new ConfigHelper("config.toml");
    const config = cfgHelper.parse();
    console.log("Done");

    console.log("xpub:");
    console.log(config.destinationWallet.xpub.toBase58());

    console.log("start index:");
    console.log(config.destinationWallet.startIndex);

    console.log("fee rate:");
    console.log(config.feeRate);

    console.log("variation:");
    console.log(config.feeVariation);

    console.log("network:");
    console.log(config.network === bitcoin.networks.bitcoin ? "mainnet" : "testnet");

    const utxos = config.utxos;
    if (utxos.length === 0) {
        console.error("No UTXOs found");
        process.exit(1);
    }

    let utxoPrivkeyMap: Map<import("./model/utxo").UTXO, Buffer[]>;

    if (config.sourceWallet.seeds.length > 0) {
        console.log(`Multisig: ${config.sourceWallet.threshold}-of-${config.sourceWallet.seeds.length}`);
        const rootXprvs: BIP32Interface[] = [];
        for (let i = 0; i < config.sourceWallet.seeds.length; i++) {
            const mnHelper = new MnemonicsHelper(config.sourceWallet.seeds[i]);
            mnHelper.passphrase = config.sourceWallet.passphrases[i] ?? "";
            const seed = mnHelper.generateSeed();
            rootXprvs.push(bip32.fromSeed(seed, config.network));
        }
        utxoPrivkeyMap = new UTXOPrivkeyHelper(config, rootXprvs).buildMap();
    } else {
        const mnHelper = new MnemonicsHelper(config.sourceWallet.seed);
        mnHelper.passphrase = config.sourceWallet.passphrase;
        const seed = mnHelper.generateSeed();
        const rootXprv = bip32.fromSeed(seed, config.network);
        utxoPrivkeyMap = new UTXOPrivkeyHelper(config, rootXprv).buildMap();
    }

    const allTransactions = new TransactionHelper(config, utxoPrivkeyMap).createTransactions();

    const report = new Report(allTransactions).writeReport();

    const txHex = allTransactions.map(t => t.transaction.toHex());

    fs.writeFileSync("tx-report.txt", report);
    fs.writeFileSync("raw-txs.txt", txHex.join("\n"));
    console.log(`Wrote ${allTransactions.length} transaction(s) to raw-txs.txt`);
    console.log(`Wrote report with transactions' summary to tx-report.txt`);
}

main();
