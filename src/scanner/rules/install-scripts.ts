import { Rule, Severity } from "../../report/types.js";

export const installScriptRules: Rule[] = [
  {
    id: "INST-001",
    category: "Suspicious Install Scripts",
    severity: Severity.HIGH,
    description: "npm lifecycle script runs code (preinstall/postinstall/prepare)",
    patterns: [
      /"(?:preinstall|postinstall|preuninstall|postuninstall|prepare)"\s*:\s*"(?!(?:husky|patch-package|ngcc|node-gyp))/g,
    ],
    fileFilter: /package\.json$/,
  },
  {
    id: "INST-002",
    category: "Suspicious Install Scripts",
    severity: Severity.CRITICAL,
    description: "Install script executes shell commands or downloads code",
    patterns: [
      /"(?:preinstall|postinstall)"\s*:\s*"[^"]*(?:curl|wget|bash|sh |node\s+-e|powershell)/g,
    ],
    fileFilter: /package\.json$/,
  },
  {
    id: "INST-003",
    category: "Suspicious Install Scripts",
    severity: Severity.HIGH,
    description: "Python setup.py with suspicious commands in install step",
    patterns: [
      /class\s+\w*[Ii]nstall.*:[\s\S]*?(?:subprocess|os\.system|exec)\s*\(/g,
    ],
    fileFilter: /setup\.py$/,
  },
  {
    id: "INST-004",
    category: "Suspicious Install Scripts",
    severity: Severity.MEDIUM,
    description: "Makefile with network or suspicious commands",
    patterns: [
      /(?:curl|wget|nc\s|bash\s+-c)\s+/g,
    ],
    fileFilter: /[Mm]akefile$/,
  },
];
