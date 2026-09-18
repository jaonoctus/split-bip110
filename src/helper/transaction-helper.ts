import { Psbt, payments } from "bitcoinjs-lib";
import { UTXO } from "../model/utxo";
import * as ecc from "tiny-secp256k1";
import { ECPairFactory } from "ecpair";
import { Config } from "../model/config";
import { Tx } from "../model/tx";
import { ScriptTypeEnum } from "../script-type";
import { signInputsUnified } from "./unified-signer";
const ECPair = ECPairFactory(ecc);

export class TransactionHelper {
    private _config: Config;
    private _utxoPrivkeyMap: Map<UTXO, Buffer[]>;

    constructor(config: Config, utxoPrivkeyMap: Map<UTXO, Buffer[]>) {
        this._config = config;
        this._utxoPrivkeyMap = utxoPrivkeyMap;
    }

    createTransactions(): Tx[] {
        const txs: Tx[] = [];
        const walletType = this._config.destinationWallet.scriptType;
        const fixedAddress = this._config.destinationWallet.address;
        const recvXpub = fixedAddress ? undefined : this._config.destinationWallet.xpub?.derive(0);

        let xpubIndex = this._config.destinationWallet.startIndex;

        for (const utxoGroup of this._config.utxos) {
            const recipientAddress = fixedAddress ?? walletType.toPayment(undefined, recvXpub!.derive(xpubIndex).publicKey, this._config.network).address as string;

            const dummyPsbt = this.createTx(utxoGroup, recipientAddress);
            const actualFee = this.calcFee(dummyPsbt);
            const finalPsbt = this.createTx(utxoGroup, recipientAddress, actualFee);
            this.validateOutputValue(finalPsbt, utxoGroup);

            txs.push(new Tx(finalPsbt, utxoGroup, xpubIndex));

            if (!fixedAddress) {
              xpubIndex++;
            }
        }

        return txs;
    }

    private createTx(utxoGroup: UTXO[], recipientAddress: string, fee = 0): Psbt {
        const psbt = new Psbt({ network: this._config.network });
        const rbfSequence = 0xfffffffd;
        let inputTotal = 0;

        for (const utxo of utxoGroup) {
            const privkeys = this._utxoPrivkeyMap.get(utxo) as Buffer[];
            if (!privkeys || privkeys.length === 0) {
                console.error(`Fatal: no private key found for UTXO:\n${utxo}`);
                process.exit(1);
            }

            const input: {
                hash: string;
                index: number;
                sequence: number;
                witnessUtxo: { script: Buffer; value: number };
                redeemScript?: Buffer;
                witnessScript?: Buffer;
                tapInternalKey?: Buffer;
            } = {
                hash: utxo.txid,
                index: utxo.vout,
                sequence: rbfSequence,
                witnessUtxo: {
                    script: utxo.output,
                    value: utxo.amount,
                },
            };

            if (utxo.scriptType.typeEnum === ScriptTypeEnum.P2SH) {
                const pubkey = ECPair.fromPrivateKey(privkeys[0]).publicKey;
                input.redeemScript = payments.p2wpkh({ pubkey, network: this._config.network }).output;
            } else if (utxo.scriptType.typeEnum === ScriptTypeEnum.P2WSH) {
                input.witnessScript = utxo.witnessScript;
            } else if (utxo.scriptType.typeEnum === ScriptTypeEnum.P2TR) {
                const pubkey = ECPair.fromPrivateKey(privkeys[0]).publicKey;
                input.tapInternalKey = pubkey.subarray(1);
            }

            psbt.addInput(input);
            inputTotal += utxo.amount;
        }

        psbt.addOutput({
            address: recipientAddress,
            value: inputTotal - fee,
        });

        signInputsUnified(psbt, utxoGroup, this._utxoPrivkeyMap);

        return psbt;
    }

    private calcFee(psbt: Psbt): number {
        const txSize = psbt.extractTransaction().virtualSize();
        const feeVariation = this._config.feeVariation || 0;
        const variation = (Math.random() * feeVariation) / 100;
        const feeRate = this._config.feeRate + variation;
        const fee = Math.trunc(txSize * feeRate);
        return fee;
    }

    private validateOutputValue(psbt: Psbt, utxoGroup: UTXO[]): void {
        const txValue = psbt.txOutputs[0].value;
        const dustLimit = this._config.destinationWallet.scriptType.dustAmount;

        if (txValue < dustLimit) {
            const coinStr = utxoGroup.length === 1 ? "coin" : "coins";
            const errMsg = [
                `Error: output of transaction [${txValue} sats] is below dust limit: [${dustLimit} sats]\nEither remove the following ${coinStr} or consolidate:`
            ];
            errMsg.push(...utxoGroup.map(u => `${u.prevout}, value: ${u.amountFormatted} BTC`));
            
            console.error(errMsg.join("\n"));
            process.exit(1);
        }
    }
}
