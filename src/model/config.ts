import { Network } from "bitcoinjs-lib";
import { BIP32Interface } from "bip32";
import { UTXO } from "./utxo";
import { ScriptType } from "../script-type";

export type Config = {
    sourceWallet: {
        seed: string,
        passphrase: string,
        seeds: string[],
        passphrases: string[],
        threshold: number,
    },
    destinationWallet: {
        xpub?: BIP32Interface,
        address?: string,
        startIndex: number,
        scriptType: ScriptType,
    },
    addressLimit: number,
    feeRate: number,
    feeVariation?: number,
    network: Network,
    utxos: UTXO[][],
};
