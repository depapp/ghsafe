import { Rule, Severity } from "../../report/types.js";

export const obfuscationRules: Rule[] = [
  {
    id: "OBF-001",
    category: "Code Obfuscation",
    severity: Severity.HIGH,
    description: "eval() usage detected — can execute arbitrary code",
    patterns: [
      /\beval\s*\(/g,
    ],
  },
  {
    id: "OBF-002",
    category: "Code Obfuscation",
    severity: Severity.HIGH,
    description: "Function constructor used to execute dynamic code",
    patterns: [
      /new\s+Function\s*\(/g,
      /Function\s*\(\s*['"`]/g,
    ],
  },
  {
    id: "OBF-003",
    category: "Code Obfuscation",
    severity: Severity.HIGH,
    description: "Long Base64-encoded string (potential hidden payload)",
    patterns: [
      /['"`][A-Za-z0-9+/=]{80,}['"`]/g,
    ],
  },
  {
    id: "OBF-004",
    category: "Code Obfuscation",
    severity: Severity.HIGH,
    description: "Hex-encoded string (potential hidden payload)",
    patterns: [
      /['"`](?:\\x[0-9a-fA-F]{2}){10,}['"`]/g,
    ],
  },
  {
    id: "OBF-005",
    category: "Code Obfuscation",
    severity: Severity.MEDIUM,
    description: "Buffer.from with base64 decoding",
    patterns: [
      /Buffer\.from\s*\([^)]+,\s*['"`]base64['"`]\s*\)/g,
    ],
  },
  {
    id: "OBF-006",
    category: "Code Obfuscation",
    severity: Severity.MEDIUM,
    description: "atob() used for Base64 decoding",
    patterns: [
      /\batob\s*\(/g,
    ],
  },
  {
    id: "OBF-007",
    category: "Code Obfuscation",
    severity: Severity.HIGH,
    description: "String concatenation building suspicious strings character by character",
    patterns: [
      /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}/g,
    ],
  },
  {
    id: "OBF-008",
    category: "Code Obfuscation",
    severity: Severity.MEDIUM,
    description: "Dynamic property access with computed key",
    patterns: [
      /\w+\[['"`]\\x[0-9a-fA-F]/g,
      /\w+\[\s*atob\s*\(/g,
    ],
  },
];
