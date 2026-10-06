# split-bip110

A tool to split BIP110 coins from BTC by transferring UTXOs one-to-one to new addresses of a separate wallet.

## How it works

Each UTXO is sent to a unique receive address on the destination wallet. UTXOs are **not consolidated**, except when:

- They share the same address (automatic grouping)
- They are surrounded by `[` `]` brackets in the UTXO file

Every input is signed with the [unified sighash](https://github.com/bitcoinknots/bitcoin/blob/8c85b1585dac23f964e2dd32045624de7f02aa58/doc/unified-sighash.md) (`SIGHASH_ALL | SIGHASH_UNIFIED`, hash type `0x21`), which is specific to the BIP110 chain. A transaction signed this way is **invalid on the regular BTC chain** (Bitcoin Core rejects it with "Signature hash type missing or not understood"), and therefore cannot be replayed onto it.

To check your transactions, you can verify, for example, they are **valid** on BIP110's [mempool.guide](https://mempool.guide/tx/test) and **invalid** on BTC's [mempool.space](https://mempool.space/tx/test).

## Usage

Download the binary for your platform from the [releases](../../releases) page and run it with no arguments. It walks you through the split:

1. **Descriptor.** Paste the output descriptor of the wallet holding the coins (in Sparrow: *Settings → Export → Output Descriptor*). Supported: `wpkh(KEY)`, `tr(KEY)`, `sh(wpkh(KEY))`, `pkh(KEY)` and `wsh(sortedmulti(M,KEY,...))`, with mainnet xpubs. Multipath `/<0;1>/*` descriptors scan receive and change. A receive-only `/0/*` descriptor also scans the matching `/1/*` change branch.
2. **Server.** Choose where to read the BIP110 chain: [mempool.guide](https://mempool.guide)'s Esplora API, mempool.guide's Electrum server (`ssl://electrs.orangepill.ovh:50002`), or your own Esplora or Electrum server (`ssl://host:50002` or `tcp://host:50001`). Before using a server, the tool checks that its block at height 961,635 matches the expected chain, so a BTC server is refused for BIP110 and the other way around.
3. **Scan.** The tool derives your addresses locally and asks the server about each one until it finds 20 unused addresses in a row (`--gap-limit` changes this).
4. **Coins.** Pick the coins to split. By default each coin gets its own transaction (coins on the same address stay together). You can also consolidate everything into one transaction.
5. **Destination.** An xpub/ypub/zpub or an output descriptor of a new wallet (a fresh receive address per transaction), or a single address, such as an exchange deposit.
6. **Fee rate.** Suggested from the server when available.
7. **Signing.** Either:
   - **Export unsigned PSBTs** (recommended): writes `tx-NNN.psbt`, `unsigned-psbts.txt` and `tx-report.txt`. Each input requests sighash type `0x21`, so the signer must support BIP110's unified sighash; regular and hardware wallets do not.
   - **Type seed words and passphrase** (hot wallet, dangerous): the tool checks the seed against the descriptor's key fingerprints and signs locally, writing `raw-txs.txt` and `tx-report.txt`. Multisig asks for as many seeds as the threshold. Seed words and passphrases stay in memory only and are never written to disk. Requires key origins (`[fingerprint/path]`) in the descriptor.

8. **Bitcoin (optional).** Finally, the tool asks whether to also move the same coins on Bitcoin (BTC) to a new wallet. If you say yes, the same questions repeat for the BTC chain (default servers: mempool.space or Blockstream's Electrum server). Coins you just split on BIP110 that still exist on BTC are preselected. BTC transactions are signed the normal way, so the PSBTs work with Sparrow, hardware wallets and any other PSBT signer.

   **Broadcast and confirm the BIP110 transactions first.** A normally signed BTC transaction may also be valid on the BIP110 chain while the same coins are unspent there, so broadcasting it first could move your BIP110 coins too.

Nothing is broadcast. Every run writes to a new folder (`split-bip110_<descriptor-id>_<time>/` for BIP110, `move-btc_<descriptor-id>_<time>/` for BTC) and never overwrites earlier output.

### Saved scans

After each scan the coins are saved to `delete_later_<fingerprints>_<descriptor-id>_<time>.csv` (BTC scans: `delete_later_btc_...`). Next time you enter the same descriptor, you can do a quick refresh (re-check those coins and only scan addresses after the last used one), a full rescan, or reuse the saved coins without connecting. Each scan writes a new file; older files are never overwritten. The file name and the `# descriptor:` header record which descriptor the coins belong to, and a file that does not match the descriptor is ignored. The file uses Sparrow's CSV format (the label column holds `branch/index`), so it also works as `utxo_file` for the config file mode below. Delete these files whenever you like: they hold your addresses and balances, but no keys.

### Privacy

- **Connections.** No compact block filters are available for the BIP110 chain yet, so scanning asks the server about each address. Your descriptor and xpub never leave your machine, but the server sees your IP address and every address queried, and can link them as one wallet. Use your own server, a VPN or Tor to limit this. The tool shows this notice and asks before it connects.
- **Linking coins.** Your pre-split coins exist on both chains. Spending several of them in one transaction, or sending several of them to the same address, shows on the BIP110 chain that they have one owner, even if you never linked them on BTC. The tool warns before building such transactions. Use one transaction per coin and an xpub destination to avoid this. If you do link coins here, consider coinjoining the same coins on BTC with [Wasabi Wallet](https://wasabiwallet.io) so the link does not carry over.

### Options

Every question can be answered with a flag; questions without a flag are still asked. Run `split-bip110 --help` for the full list.

```
--descriptor <descriptor>        output descriptor of the wallet holding the coins
-y, --yes                        accept the privacy notice, privacy warnings and confirmations
--btc / --no-btc                 run or skip the Bitcoin step without asking

--esplora <url>                  Esplora API of the BIP110 chain
--electrum <server>              Electrum server of the BIP110 chain, e.g. ssl://host:50002
--scan refresh|full|offline      what to do with a saved scan
--coins all|txid:vout,...        coins to move
--grouping separate|consolidate  one transaction per coin, or one for all
--dest-address <address>         send everything to one address
--dest-xpub <xpub>               send to a new wallet's account xpub/ypub/zpub (with --dest-type for xpub)
--dest-type segwit|taproot|p2sh|legacy
--dest-descriptor <descriptor>   send to a new wallet's output descriptor
--dest-index <n>                 first receive index of the destination wallet (default: 0)
--fee-rate <sat/vB>              fee rate
--sign psbt|hot                  signing method

--btc-esplora, --btc-electrum, --btc-scan, --btc-coins, --btc-grouping, --btc-dest-*,
--btc-fee-rate, --btc-sign       the same answers for the Bitcoin step; --btc-coins also takes
                                 "moved" (the coins moved on BIP110 in this run)

--electrum-self-signed           accept self-signed TLS certificates from Electrum servers
--gap-limit <n>                  consecutive unused addresses before a scan stops (default: 20)
--scan-dir <dir>                 where delete_later_*.csv scan files are read and written (default: .)
--output-dir <dir>               where output folders are created (default: .)
```

Example of a fully non-interactive run that exports PSBTs on both chains:

```bash
split-bip110 --descriptor "wpkh([fingerprint/84h/0h/0h]xpub.../<0;1>/*)" \
  --esplora https://mempool.guide/api --scan full --coins all --grouping separate \
  --dest-xpub zpub... --fee-rate 2 --sign psbt \
  --btc --btc-esplora https://mempool.space/api --btc-scan full --btc-coins moved --btc-grouping separate \
  --btc-dest-descriptor "tr([fingerprint/86h/0h/0h]xpub.../<0;1>/*)" --btc-fee-rate 3 --btc-sign psbt --yes
```

Seed words and passphrases are never accepted as flags (they would end up in your shell history). With `--sign hot` the tool still asks for them, and the hot wallet warning is shown even with `--yes`. If a flag answer leads to a problem (a coin below the dust limit, or declining a confirmation), the tool falls back to asking the questions. Without a terminal it stops and says which question needs a flag.

### Docker

A prebuilt image for `linux/amd64`, `linux/arm64` and `linux/arm/v7` is published as [`jaonoctus/split-bip110`](https://hub.docker.com/r/jaonoctus/split-bip110):

```bash
docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD:/data" jaonoctus/split-bip110
```

- `-it` is needed for the interactive questions. A fully flag-driven run (see [Options](#options)) also works without it.
- The container works in `/data`. **Mount a directory there with `-v`**, or the PSBTs, signed transactions and scan files are deleted with the container; the tool warns at startup when nothing is mounted.
- `--user` makes the written files belong to you instead of the container's user.
- Options go after the image name, e.g. `jaonoctus/split-bip110 --electrum ssl://electrs.orangepill.ovh:50002`. The config file mode is `jaonoctus/split-bip110 legacy`, reading `config.toml` from the mounted directory.

To build the image yourself instead:

```bash
docker build -t split-bip110 .
docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD:/data" split-bip110
```

The image is built only from `package.json`, `package-lock.json`, `tsconfig.json` and `src/`, so a `config.toml` with seed words is never copied into it.

## Config file mode

The original non-interactive flow is still available as `split-bip110 legacy [--config config.toml]`. It reads a UTXO CSV file and the seed words from `config.toml`.


### 1. Export UTXO list from Sparrow Wallet

Export your UTXO list as a CSV file. The expected format matches Sparrow's export:

```csv
Date (UTC),Output,Address,Label,Value
2024-12-14 06:40:21,7c87ca...:2,tb1qt35r...,label,0.00333454
```

To consolidate specific UTXOs into one transaction, wrap them with brackets:

```csv
[
2024-12-14 06:40:21,7c87ca...:2,tb1qt35r...,,0.00333454
2024-12-14 06:40:21,af378d...:1,tb1q5ecv...,,0.00103000
]
2024-12-14 06:42:21,a00ab5...:0,tb1qgu3r...,,0.00077221
```

In the example above, the first 2 UTXOs will be joined into a single transaction.

### 2. Set up your wallets

**Source wallet.** This is the wallet you are migrating from. It can be a regular HD wallet (single seed) or an m-of-n multisig wallet. For multisig, you need the seed words (and optional passphrases) of all co-signers. The tool uses BIP48 derivation (`m/48'/coin'/0'/2'/0|1/index`) with BIP67-sorted pubkeys, matching Sparrow's multisig wallet format.

**Destination wallet.** Create a new wallet to host only your BIP110 coins (Sparrow, Electrum, Iancoleman's BIP39, etc.) and take note of the xpub. Alternatively, if you want all coins sent to a single address (for example, an exchange), you can skip the xpub and set `address` in the config instead.

### 3. Configure `config.toml`

Fill in the following fields:

```toml
# Path to the exported UTXO CSV file
utxo_file = "your-utxos.csv"

# Network: mainnet or testnet
network = "mainnet"

[source_wallet]
# Option 1: single-sig:
# Fill seed with the seed words and optional BIP39 passphrase
seed = "word1 word2 ... wordN"
passphrase = ""

# Option 2: multisig (m-of-n):
# Fill all seeds and the threshold. If 2-of-3, there will be 3 seeds/passphrases and threshold = 2.
seed1 = "word1 word2 ... wordN"
passphrase1 = ""
seed2 = "word1 word2 ... wordN"
passphrase2 = ""
seed3 = "word1 word2 ... wordN"
passphrase3 = ""
threshold = 2

# Max addresses to derive when searching for UTXO private keys (default: 2000)
address_limit = 2000

[destination_wallet]
# Option 1: xpub of the receiving wallet
xpub = "xpub..."
# Address type: segwit, taproot, legacy, or p2sh
type = "segwit"

# Option 2: send all transactions to a single address (ignores xpub/type/initial_index)
# address = "bc1q..."

[transaction]
# Fee rate in sat/vb (minimum: 1, default: 1)
fee_rate = 1.03
# Random fee variation in basis points (default: 0)
fee_variation = 50
```

### 4. Run

Place `config.toml` and your UTXO CSV file alongside the binary, then run `split-bip110 legacy`.

This produces two files:

- `raw-txs.txt` — raw transaction hex (one per line)
- `tx-report.txt` — summary report with fees and amounts

## Compiling from source

```bash
npm install
npm run pkg
```

## Warning

**Always verify the generated transactions before broadcasting.** For example, make sure the destination addresses are what you expect.

**Important warning about legacy (P2PKH) wallets in config file mode**: since this mode runs offline, it has to fully trust the UTXO CSV file and **cannot check if the UTXO value is correct**. This is not a problem for segwit (including taproot) UTXOs, because the values are signed, but for legacy UTXOs, **you have to make sure the values are correct or part of the UTXO could be wasted in fees**. Sparrow will export the CSV file with correct values, but keep in mind this warning if you're editing the CSV file!

This software comes with no warranty. You are solely responsible for verifying that the transactions are correct. Bugs could result in loss of funds.

## Donation

If this project helped you earn something and you are feeling grateful, you can share a bit with:

- Lightning: `fiscalhawk44@walletofsatoshi.com`
- Silent Payments: `sp1qqdx6zdc0guc4ncu2wv74hhy2ql8wnxhas0hl9q8sxdxhz253c6xq5quj7kedy36lfl4yau7cph0dtzxvltzwwdutw4ct5x9clrvpkz8nxv0kpwdt`
- BIP47: `PM8TJgutCtE1GK1Lf6WUTRLzVNcBvNRXjKueKgpQ36dc6Dry3w5oCYz5NEVk7GvNpXAMdrioi6DVytk1P4RBGjXpLw1VFfTm2dNrdtTUWQCQtcjDwPVm` or PayNym: [+otto](https://paynym.rs/+otto)
- XMR: `84ASExDrrRGBgmYFCzFf6sKK4Q3gwynpzBqp3ZZfNUb4WpbAGJUJ2nrSAEfNLv3FacD5suRMLUzNCAL6XkR7bhe9QKfchu7`
- Or ask for an address on `cautious_uncrown054@simplelogin.com`.

## License

This project is free to use, copy, and modify. The author is not responsible for any bugs or issues that may cause financial loss. Use at your own risk.
