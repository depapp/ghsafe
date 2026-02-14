import { Rule, Severity } from "../../report/types.js";

export const persistenceRules: Rule[] = [
  {
    id: "PERS-001",
    category: "Persistence",
    severity: Severity.HIGH,
    description: "Crontab manipulation detected",
    patterns: [
      /crontab/g,
      /\/etc\/cron/g,
      /exec\s*\([^)]*cron/g,
    ],
  },
  {
    id: "PERS-002",
    category: "Persistence",
    severity: Severity.HIGH,
    description: "Modifying shell profile/rc files",
    patterns: [
      /(?:writeFileSync|writeFile|appendFileSync|appendFile)\s*\([^)]*(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile)/g,
    ],
  },
  {
    id: "PERS-003",
    category: "Persistence",
    severity: Severity.HIGH,
    description: "Creating systemd service or launch agent",
    patterns: [
      /(?:writeFileSync|writeFile)\s*\([^)]*(?:systemd|LaunchAgents|LaunchDaemons|init\.d)/g,
    ],
  },
  {
    id: "PERS-004",
    category: "Persistence",
    severity: Severity.HIGH,
    description: "Windows registry manipulation",
    patterns: [
      /(?:exec|spawn)\s*\([^)]*reg\s+(?:add|delete|import)/gi,
      /HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT)/g,
    ],
  },
  {
    id: "PERS-005",
    category: "Persistence",
    severity: Severity.HIGH,
    description: "Startup directory modification",
    patterns: [
      /(?:writeFileSync|writeFile|copyFileSync)\s*\([^)]*(?:Startup|autostart|rc\.local)/gi,
    ],
  },
];
