import * as ecc from "tiny-secp256k1";
import { BIP32Factory } from "bip32";
import { initEccLib } from "bitcoinjs-lib";

export const bip32 = BIP32Factory(ecc);
initEccLib(ecc);
