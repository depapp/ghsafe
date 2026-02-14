import { Rule, Severity } from "../../report/types.js";

export const executionRules: Rule[] = [
  {
    id: "EXEC-001",
    category: "Dangerous Execution",
    severity: Severity.HIGH,
    description: "child_process exec/execSync used to run shell commands",
    patterns: [
      /(?:require|import)\s*\(?\s*['"`]child_process['"`]\s*\)?/g,
      /child_process/g,
    ],
  },
  {
    id: "EXEC-002",
    category: "Dangerous Execution",
    severity: Severity.HIGH,
    description: "Shell command execution detected",
    patterns: [
      /\bexecSync\s*\(\s*['"`]/g,
      /\bexec\s*\(\s*['"`](?:curl|wget|bash|sh|powershell|cmd|python|node|rm|chmod)/g,
      /\bspawnSync?\s*\(\s*['"`](?:bash|sh|cmd|powershell)/g,
    ],
  },
  {
    id: "EXEC-003",
    category: "Dangerous Execution",
    severity: Severity.CRITICAL,
    description: "Downloading and executing remote script",
    patterns: [
      /(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|node|python)/g,
      /exec\s*\(\s*['"`](?:curl|wget)\s+.*\|\s*(?:bash|sh)/g,
    ],
  },
  {
    id: "EXEC-004",
    category: "Dangerous Execution",
    severity: Severity.HIGH,
    description: "Dynamic require or import with variable path",
    patterns: [
      /require\s*\(\s*(?!['"`])[^)]+\)/g,
      /import\s*\(\s*(?!['"`])[^)]+\)/g,
    ],
  },
  {
    id: "EXEC-005",
    category: "Dangerous Execution",
    severity: Severity.MEDIUM,
    description: "Process manipulation (exit, kill signals)",
    patterns: [
      /process\.kill\s*\(/g,
    ],
  },
];
