import { Rule, Severity } from "../../report/types.js";

export const cryptoRules: Rule[] = [
  {
    id: "CRYPTO-001",
    category: "Crypto Mining",
    severity: Severity.CRITICAL,
    description: "Cryptocurrency mining pool connection detected",
    patterns: [
      /['"`](?:stratum\+tcp|stratum\+ssl):\/\//g,
      /(?:pool|mine|mining).*(?:monero|xmr|bitcoin|btc|ethereum|eth)/gi,
    ],
  },
  {
    id: "CRYPTO-002",
    category: "Crypto Mining",
    severity: Severity.CRITICAL,
    description: "Known crypto mining library imported",
    patterns: [
      /(?:require|import)\s*\(?\s*['"`](?:coinhive|cryptonight|xmrig|minero)/gi,
    ],
  },
  {
    id: "CRYPTO-003",
    category: "Crypto Mining",
    severity: Severity.HIGH,
    description: "WebAssembly loading (common in browser-based miners)",
    patterns: [
      /WebAssembly\.instantiate.*(?:mine|hash|crypto)/gis,
    ],
  },
  {
    id: "CRYPTO-004",
    category: "Crypto Mining",
    severity: Severity.HIGH,
    description: "Cryptocurrency wallet address pattern detected",
    patterns: [
      /['"`][13][a-km-zA-HJ-NP-Z1-9]{25,34}['"`]/g, // Bitcoin
      /['"`]0x[0-9a-fA-F]{40}['"`]/g, // Ethereum
      /['"`]4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}['"`]/g, // Monero
    ],
  },
];
