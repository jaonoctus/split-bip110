// What differs between the two chains the wizard can move coins on.
export type ChainProfile = {
    key: "bip110" | "bitcoin";
    name: string;
    defaultEsplora: string;
    defaultElectrum: string;
    defaultEsploraName: string;
    defaultElectrumName: string;
    // Hash of block 961635, after the split (961632) and before BIP110's BLAKE2b switch (961640),
    // so it is still a plain double SHA-256 of an 80-byte header on both chains.
    checkHash: string;
    // "unified" signs with SIGHASH_ALL|SIGHASH_UNIFIED (BIP110 only); "standard" signs like any BTC wallet.
    sighash: "unified" | "standard";
    // Inserted after "delete_later_" in scan file names.
    scanTag: string;
    outputPrefix: string;
    explorerTx: string;
    // Block explorer; transactions are at `${explorer}/tx/${txid}`.
    explorer: string;
};

export const CHECK_HEIGHT = 961635;

export const BIP110: ChainProfile = {
    key: "bip110",
    name: "BIP110",
    defaultEsplora: "https://mempool.guide/api",
    defaultElectrum: "ssl://electrs.orangepill.ovh:50002",
    defaultEsploraName: "mempool.guide Esplora API",
    defaultElectrumName: "mempool.guide Electrum server",
    checkHash: "00000000000000000000c705b7a0a847d2713d73da4a1b20cea3dfdd617fa651",
    sighash: "unified",
    scanTag: "",
    outputPrefix: "split-bip110",
    explorerTx: "https://mempool.guide/tx/test",
    explorer: "https://mempool.guide",
};

export const BITCOIN: ChainProfile = {
    key: "bitcoin",
    name: "Bitcoin (BTC)",
    defaultEsplora: "https://mempool.space/api",
    defaultElectrum: "ssl://electrum.blockstream.info:50002",
    defaultEsploraName: "mempool.space Esplora API",
    defaultElectrumName: "Blockstream Electrum server",
    checkHash: "0000000000000000000002404916f6a072087b5a9105b42955dbc7f96950f972",
    sighash: "standard",
    scanTag: "btc_",
    outputPrefix: "move-btc",
    explorerTx: "https://mempool.space/tx/test",
    explorer: "https://mempool.space",
};
