import { Network, networks } from "bitcoinjs-lib";
import { ScriptType } from "../script-type";

export class UTXO {
    private _txid: string;
    private _vout: number;
    private _amount: number;
    private _address: string;
    private _scriptType: ScriptType;
    private _network: Network;
    private _threshold: number = 0;
    private _witnessScript?: Buffer;

    constructor(txid: string, vout: number, amount: number, address: string) {
        this._txid = txid;
        this._vout = vout;
        this._amount = amount;
        this._address = address;
        if (address[0] === "1" || address[0] === "3" || address.startsWith("bc1")) {
            this._network = networks.bitcoin;
        } else {
            this._network = networks.testnet;
        }

        this._scriptType = ScriptType.fromAddress(address, this._network);
    }

    get prevout(): string {
        return `${this._txid}:${this._vout}`;
    }

    get txid(): string {
        return this._txid;
    }

    get vout(): number {
        return this._vout;
    }

    get amount(): number {
        return this._amount;
    }

    get amountFormatted(): string {
        const btc = this.amount / 1e8;
        return btc.toFixed(8);
    }

    get address(): string {
        return this._address;
    }
    
    get scriptType(): ScriptType {
        return this._scriptType;
    }

    get output(): Buffer {
        return this._scriptType.toPayment(this._address, undefined, this._network).output as Buffer;
    }

    get threshold(): number {
        return this._threshold;
    }

    set threshold(value: number) {
        this._threshold = value;
    }

    get witnessScript(): Buffer | undefined {
        return this._witnessScript;
    }

    set witnessScript(value: Buffer | undefined) {
        this._witnessScript = value;
    }
}