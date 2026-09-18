import { Network, Payment, payments, networks, address as btcAddress } from "bitcoinjs-lib";

export enum ScriptTypeEnum {
    P2PKH,
    P2SH,
    P2WPKH,
    P2TR,
    P2WSH,
};

export class ScriptType {
    static P2PKH = new ScriptType(ScriptTypeEnum.P2PKH);
    static P2SH = new ScriptType(ScriptTypeEnum.P2SH);
    static P2WPKH = new ScriptType(ScriptTypeEnum.P2WPKH);
    static P2TR = new ScriptType(ScriptTypeEnum.P2TR);
    static P2WSH = new ScriptType(ScriptTypeEnum.P2WSH);

    private _typeEnum: ScriptTypeEnum;

    private constructor(typeEnum: ScriptTypeEnum) {
        this._typeEnum = typeEnum;
    }

    get typeEnum(): ScriptTypeEnum {
        return this._typeEnum;
    }

    get bip(): number {
        switch (this.typeEnum) {
            case ScriptTypeEnum.P2PKH:
                return 44;
            case ScriptTypeEnum.P2SH:
                return 49;
            case ScriptTypeEnum.P2WPKH:
                return 84;
            case ScriptTypeEnum.P2TR:
                return 86;
            case ScriptTypeEnum.P2WSH:
                return 48;
        }
    }

    get dustAmount(): number { //source: https://x.com/OrangeSurfBTC/status/1924681860741005339
        switch (this.typeEnum) {
            case ScriptTypeEnum.P2PKH:
                return 546;
            case ScriptTypeEnum.P2SH:
                return 540;
            case ScriptTypeEnum.P2WPKH:
                return 294;
            case ScriptTypeEnum.P2TR:
                return 330;
            case ScriptTypeEnum.P2WSH:
                return 330;
        }
    }

    toPayment(address?: string, pubkey?: Buffer, network?: Network): Payment {
        if ((!address && !pubkey) || (!!address && !!pubkey)) {
            throw new Error("toPayment requires address OR pubkey");
        }

        const options: Payment = { network: network || networks.bitcoin };
        if (!!address) {
            options.address = address;
        } else {
            if (this._typeEnum === ScriptTypeEnum.P2SH) {
                options.redeem = payments.p2wpkh({ pubkey: pubkey as Buffer, network: options.network });
            } else if (this._typeEnum === ScriptTypeEnum.P2TR) {
                options.internalPubkey = pubkey?.subarray(1);
            } else {
                options.pubkey = pubkey;
            }
        }

        switch (this._typeEnum) {
            case ScriptTypeEnum.P2PKH:
                return payments.p2pkh(options);
            case ScriptTypeEnum.P2SH:
                return payments.p2sh(options);
            case ScriptTypeEnum.P2WPKH:
                return payments.p2wpkh(options);
            case ScriptTypeEnum.P2TR:
                return payments.p2tr(options);
            case ScriptTypeEnum.P2WSH:
                if (!address) {
                    throw new Error("P2WSH toPayment requires an address");
                }
                return { output: btcAddress.toOutputScript(address, options.network) } as Payment;
        }
    }

    toString(): string {
        return ScriptTypeEnum[this._typeEnum];
    }

    static fromAddress(address: string, network = networks.bitcoin): ScriptType {
        const mainnet = network === networks.bitcoin;

        if ((mainnet && address[0] === "1") || (!mainnet && ["m", "n"].includes(address[0]))) {
            return ScriptType.P2PKH;
        }

        if ((mainnet && address[0] === "3") || (!mainnet && address[0] === "2")) {
            return ScriptType.P2SH;
        }

        const bechPrefix = address.slice(0, 4);
        if ((mainnet && bechPrefix === "bc1q") || (!mainnet && bechPrefix === "tb1q")) {
            const decoded = btcAddress.toOutputScript(address, network);
            if (decoded.length - 1 === 33) {
                return ScriptType.P2WSH;
            }
            return ScriptType.P2WPKH;
        }

        if ((mainnet && bechPrefix === "bc1p") || (!mainnet && bechPrefix === "tb1p")) {
            return ScriptType.P2TR;
        }

        console.error(`Invalid address and/or network combination: ${address}, ${mainnet ? "mainnet" : "testnet"}`);
        process.exit(1);
    }
}