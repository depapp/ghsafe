import { Rule, Severity } from "../../report/types.js";

export const exfiltrationRules: Rule[] = [
  {
    id: "EXF-001",
    category: "Data Exfiltration",
    severity: Severity.CRITICAL,
    description: "Accessing environment variables for tokens/secrets",
    patterns: [
      /process\.env\s*[\[.](?:.*(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|API_KEY|AUTH|PRIVATE))/gi,
    ],
  },
  {
    id: "EXF-002",
    category: "Data Exfiltration",
    severity: Severity.CRITICAL,
    description: "Reading .env file directly",
    patterns: [
      /(?:readFileSync|readFile|createReadStream)\s*\([^)]*\.env/g,
    ],
  },
  {
    id: "EXF-003",
    category: "Data Exfiltration",
    severity: Severity.CRITICAL,
    description: "Accessing SSH keys or sensitive config files",
    patterns: [
      /(?:readFileSync|readFile|createReadStream)\s*\([^)]*(?:\.ssh|id_rsa|id_ed25519|\.gnupg|\.aws\/credentials|\.npmrc|\.pypirc)/g,
    ],
  },
  {
    id: "EXF-004",
    category: "Data Exfiltration",
    severity: Severity.HIGH,
    description: "Accessing browser data (cookies, local storage, saved passwords)",
    patterns: [
      /(?:readFileSync|readFile|createReadStream|readdir)\s*\([^)]*(?:Cookies|Login Data|Local Storage|chrome|firefox|brave|opera)/gi,
    ],
  },
  {
    id: "EXF-005",
    category: "Data Exfiltration",
    severity: Severity.HIGH,
    description: "Collecting system information for fingerprinting",
    patterns: [
      /os\.(?:hostname|userInfo|homedir|platform|arch|networkInterfaces)\s*\(\).*(?:fetch|http|request|axios|send|post)/gis,
    ],
  },
  {
    id: "EXF-006",
    category: "Data Exfiltration",
    severity: Severity.HIGH,
    description: "Bulk environment variable collection",
    patterns: [
      /JSON\.stringify\s*\(\s*process\.env\s*\)/g,
      /Object\.(?:keys|entries|values)\s*\(\s*process\.env\s*\)/g,
    ],
  },
  {
    id: "EXF-007",
    category: "Data Exfiltration",
    severity: Severity.CRITICAL,
    description: "Accessing cryptocurrency wallet files",
    patterns: [
      /(?:readFileSync|readFile|readdir)\s*\([^)]*(?:wallet\.dat|\.bitcoin|\.ethereum|\.electrum|metamask|phantom)/gi,
    ],
  },
];
