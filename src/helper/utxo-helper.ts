import * as fs from "fs";
import { UTXO } from "../model/utxo";

export class UTXOHelper {
    private readonly regexOutput = /^[0-9a-f]{64}:\d+$/;
    private readonly regexAddress = /^(1|3|m|n|2|bc1|tb1)\w{20,}$/;
    private readonly regexAmount = /^(\d+\.)?\d+$/;

    private utxoContent: string;

    constructor(utxoFile: string) {
        this.utxoContent = fs.readFileSync(utxoFile).toString().trim();
    }

    // Returns a diagnostic hint if the value contains any non-ASCII character
    // (e.g. full-width digits U+FF10-U+FF19, non-breaking spaces U+00A0/U+202F),
    // otherwise returns an empty string.
    private nonAsciiHint(value: string): string {
        const offenders: string[] = [];
        for (const ch of value) {
            if (ch.charCodeAt(0) > 0x7f) {
                const hex = ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0");
                offenders.push(`${ch} (U+${hex})`);
            }
        }
        if (offenders.length === 0) return "";
        return `\n  contains non-ASCII character(s): ${offenders.join(", ")} (likely full-width digits or invisible chars) — re-type this field with plain ASCII.`;
    }

    parse(): UTXO[][] {
        const utxos: UTXO[][] = [];
        const mapAddressIndex = new Map<string, number>();

        const lines = this.utxoContent.split("\n");

        let insideUtxoGroup = false;
        let groupIndex = -1;

        for (let [i, line] of lines.entries()) {
            const lineNumber = i + 1;
            line = line.trim();

            if (!line || line[0] === "#" || line.startsWith("Date")) {
                continue;
            }

            const openingBracket = line[0] === "[";
            const closingBracket = line[0] === "]";
            if (openingBracket || closingBracket) {
                if (line.length >= 2) {
                    console.error(`Error on line ${lineNumber}: bracket should be the only character`);
                    process.exit(1);
                }

                if ((openingBracket && insideUtxoGroup) || (closingBracket && !insideUtxoGroup)) {
                    console.error(`Error on line ${lineNumber}: unmatched brackets`);
                    process.exit(1);
                }

                insideUtxoGroup = openingBracket;
                groupIndex = -1;
                continue;
            }

            const tokens = line.split(",");
            if (tokens.length !== 5) {
                console.error(`Error on line ${lineNumber}: expected 5 comma-separated tokens (Date,Output,Address,Label,Value), got ${tokens.length}`);
                process.exit(1);
            }

            const [, outputStr, addressStr, , valueStr] = tokens.map(t => t.trim());

            if (!this.regexOutput.exec(outputStr)) {
                console.error(`Error on line ${lineNumber}: invalid output: "${outputStr}"${this.nonAsciiHint(outputStr)}`);
                process.exit(1);
            }
            const [txid, voutStr] = outputStr.split(":");
            const vout = parseInt(voutStr, 10);

            if (!this.regexAddress.exec(addressStr)) {
                console.error(`Error on line ${lineNumber}: invalid address: "${addressStr}"${this.nonAsciiHint(addressStr)}`);
                process.exit(1);
            }
            const address = addressStr;

            if (!this.regexAmount.exec(valueStr)) {
                console.error(`Error on line ${lineNumber}: invalid value: "${valueStr}"${this.nonAsciiHint(valueStr)}`);
                process.exit(1);
            }
            const amount = Math.round(parseFloat(valueStr) * 1e8);

            const u = new UTXO(txid, vout, amount, address);

            if (amount === 0) {
                console.error(`Error on line ${lineNumber}: value must be greater than 0`);
                process.exit(1);
            }

            // UTXO will be inserted:
            // - If the line is inside brackets, in the group enclosed by them
            // - If there's address reuse, with the other address' UTXO
            // - Otherwise, alone
            if (insideUtxoGroup) {
                if (groupIndex === -1) { // first of the group, add to UTXO array
                    utxos.push([u]);
                    groupIndex = utxos.length - 1;
                } else { // group already exists, use it
                    utxos[groupIndex].push(u);
                }
            } else {
                const addrIndex = mapAddressIndex.get(address);
                if (addrIndex !== undefined) { // address has been seen before, add to group
                    utxos[addrIndex].push(u);
                } else { // will go alone for now
                    utxos.push([u]);
                    mapAddressIndex.set(address, utxos.length - 1);
                }
            }
        }

        if (insideUtxoGroup) {
            console.error('Unmatched brackets: group not closed');
            process.exit(1);
        }

        return utxos;
    }
}
