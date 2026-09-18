import { Config } from "../model/config";
import { networks, payments } from "bitcoinjs-lib";
import { BIP32Interface } from "bip32";
import { UTXO } from "../model/utxo";
import { ScriptType, ScriptTypeEnum } from "../script-type";

type Wallet = {
    recvXprv: BIP32Interface,
    changeXprv: BIP32Interface,
    addressMap: Map<string, Buffer>,
    scriptType: ScriptType,
    keyIndex: number,
};

type KeyPair = {
    address: string,
    privkey: Buffer,
};

type AddressType = "receive" | "change";

type MultisigWallet = {
    recvXprvs: BIP32Interface[],
    changeXprvs: BIP32Interface[],
    addressMap: Map<string, { privkeys: Buffer[], witnessScript: Buffer }>,
    keyIndex: number,
};

export class UTXOPrivkeyHelper {
    private _config: Config;
    private _rootXprv: BIP32Interface;
    private _rootXprvs: BIP32Interface[];
    private _threshold: number;
    private _isMultisig: boolean;

    private _wallets = new Map<ScriptType, Wallet>();
    private _multisigWallet: MultisigWallet | undefined;

    constructor(config: Config, rootXprv: BIP32Interface | BIP32Interface[]) {
        this._config = config;
        this._isMultisig = config.sourceWallet.seeds.length > 0;

        if (this._isMultisig) {
            this._rootXprvs = rootXprv as BIP32Interface[];
            this._rootXprv = this._rootXprvs[0];
            this._threshold = config.sourceWallet.threshold;
        } else {
            this._rootXprv = rootXprv as BIP32Interface;
            this._rootXprvs = [this._rootXprv];
            this._threshold = 0;
        }
    }

    buildMap(): Map<UTXO, Buffer[]> {
        const utxoMap = new Map<UTXO, Buffer[]>();

        for (const utxoGroup of this._config.utxos) {
            utxoLoop:
            for (const utxo of utxoGroup) {
                const utxoAddress = utxo.address;
                const scriptType = ScriptType.fromAddress(utxoAddress, this._config.network);

                if (this._isMultisig && scriptType.typeEnum === ScriptTypeEnum.P2WSH) {
                    const msWallet = this.getMultisigWallet();
                    const cached = msWallet.addressMap.get(utxoAddress);

                    if (cached) {
                        utxoMap.set(utxo, cached.privkeys);
                        utxo.threshold = this._threshold;
                        utxo.witnessScript = cached.witnessScript;
                    } else {
                        while (msWallet.keyIndex < this._config.addressLimit) {
                            const recvResult = this.deriveMultisigKeyPair(msWallet, "receive");
                            const changeResult = this.deriveMultisigKeyPair(msWallet, "change");

                            msWallet.addressMap.set(recvResult.address, { privkeys: recvResult.privkeys, witnessScript: recvResult.witnessScript });
                            msWallet.addressMap.set(changeResult.address, { privkeys: changeResult.privkeys, witnessScript: changeResult.witnessScript });
                            msWallet.keyIndex++;

                            if (recvResult.address === utxoAddress) {
                                utxoMap.set(utxo, recvResult.privkeys);
                                utxo.threshold = this._threshold;
                                utxo.witnessScript = recvResult.witnessScript;
                                continue utxoLoop;
                            } else if (changeResult.address === utxoAddress) {
                                utxoMap.set(utxo, changeResult.privkeys);
                                utxo.threshold = this._threshold;
                                utxo.witnessScript = changeResult.witnessScript;
                                continue utxoLoop;
                            }
                        }

                        const msg = `Unable to find private key of ${utxoAddress}; checked first ${this._config.addressLimit} addresses.
                        If it's deeper inside the wallet, address_limit should be increased.
                        Otherwise it's not part of this seed combination or uses a different script type`;
                        console.error(msg);
                        process.exit(1);
                    }
                } else {
                    const wallet = this.getWallet(scriptType);
                    const privKey = wallet.addressMap.get(utxoAddress);

                    if (privKey) {
                        utxoMap.set(utxo, [privKey]);
                    } else {
                        while (wallet.keyIndex < this._config.addressLimit) {
                            const recvKeyPair = this.deriveKeyPair(wallet, "receive");
                            const changeKeyPair = this.deriveKeyPair(wallet, "change");

                            wallet.addressMap.set(recvKeyPair.address, recvKeyPair.privkey);
                            wallet.addressMap.set(changeKeyPair.address, changeKeyPair.privkey);
                            wallet.keyIndex++;

                            if (recvKeyPair.address === utxoAddress) {
                                utxoMap.set(utxo, [recvKeyPair.privkey]);
                                continue utxoLoop;
                            } else if (changeKeyPair.address === utxoAddress) {
                                utxoMap.set(utxo, [changeKeyPair.privkey]);
                                continue utxoLoop;
                            }
                        }

                        const msg = `Unable to find private key of ${utxoAddress}; checked first ${this._config.addressLimit} addresses.
                        If it's deeper inside the wallet, address_limit should be increased.
                        Otherwise it's not part of this seed or uses a protocol like BIP47 or Silent Payments`;
                        console.error(msg);
                        process.exit(1);
                    }
                }
            }
        }

        return utxoMap;
    }

    private getWallet(scriptType: ScriptType): Wallet {
        let wallet = this._wallets.get(scriptType);
        if (!wallet) {
            const coinType = this._config.network === networks.bitcoin ? 0 : 1;
            wallet = {
                recvXprv: this._rootXprv.derivePath(`m/${scriptType.bip}'/${coinType}'/0'/0`),
                changeXprv: this._rootXprv.derivePath(`m/${scriptType.bip}'/${coinType}'/0'/1`),
                addressMap: new Map<string, Buffer>(),
                scriptType: scriptType,
                keyIndex: 0,
            };

            this._wallets.set(scriptType, wallet);
        }

        return wallet;
    }

    private deriveKeyPair(wallet: Wallet, addressType: AddressType): KeyPair {
        const xprv = addressType === 'receive' ? wallet.recvXprv : wallet.changeXprv;
        const privkey = xprv.derive(wallet.keyIndex);
        const network = this._config.network;

        return {
            address: wallet.scriptType.toPayment(undefined, privkey.publicKey, network).address as string,
            privkey: privkey.privateKey as Buffer,
        };
    }

    private getMultisigWallet(): MultisigWallet {
        const scriptType = ScriptType.P2WSH;

        if (!this._multisigWallet) {
            const coinType = this._config.network === networks.bitcoin ? 0 : 1;
            const recvXprvs: BIP32Interface[] = [];
            const changeXprvs: BIP32Interface[] = [];

            for (const rootXprv of this._rootXprvs) {
                const account = rootXprv.derivePath(`m/${scriptType.bip}'/${coinType}'/0'/2'`);
                recvXprvs.push(account.derivePath("0"));
                changeXprvs.push(account.derivePath("1"));
            }

            this._multisigWallet = {
                recvXprvs,
                changeXprvs,
                addressMap: new Map<string, { privkeys: Buffer[], witnessScript: Buffer }>(),
                keyIndex: 0,
            };
        }

        return this._multisigWallet;
    }

    private deriveMultisigKeyPair(wallet: MultisigWallet, addressType: AddressType): {
        address: string,
        privkeys: Buffer[],
        witnessScript: Buffer,
    } {
        const xprvs = addressType === 'receive' ? wallet.recvXprvs : wallet.changeXprvs;
        const network = this._config.network;

        const pubkeys: Buffer[] = [];
        const privkeys: Buffer[] = [];

        for (const xprv of xprvs) {
            const child = xprv.derive(wallet.keyIndex);
            pubkeys.push(child.publicKey as Buffer);
            privkeys.push(child.privateKey as Buffer);
        }

        const sortedPairs = pubkeys.map((pk, i) => ({ pubkey: pk, privkey: privkeys[i] }))
            .sort((a, b) => a.pubkey.compare(b.pubkey));

        const sortedPubkeys = sortedPairs.map(p => p.pubkey);
        const sortedPrivkeys = sortedPairs.map(p => p.privkey);

        const p2ms = payments.p2ms({ m: this._threshold, pubkeys: sortedPubkeys, network });
        const p2wsh = payments.p2wsh({ redeem: p2ms, network });

        return {
            address: p2wsh.address as string,
            privkeys: sortedPrivkeys,
            witnessScript: p2wsh.redeem!.output as Buffer,
        };
    }
}
