import { Rule, Severity } from "../../report/types.js";

export const networkRules: Rule[] = [
  {
    id: "NET-001",
    category: "Network Exfiltration",
    severity: Severity.HIGH,
    description: "HTTP request to raw IP address",
    patterns: [
      /(?:fetch|axios|http|https|request|got|node-fetch)\s*[\.(]\s*['"`]https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
    ],
  },
  {
    id: "NET-002",
    category: "Network Exfiltration",
    severity: Severity.HIGH,
    description: "Webhook URL detected (Discord, Slack, etc.)",
    patterns: [
      /['"`]https?:\/\/(?:discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com|webhook\.site|pipedream\.net|requestbin)/gi,
    ],
  },
  {
    id: "NET-003",
    category: "Network Exfiltration",
    severity: Severity.HIGH,
    description: "Data sent via POST/PUT with sensitive variable names",
    patterns: [
      /(?:fetch|axios|http|request)\s*[\.(].*(?:method|type)\s*:\s*['"`](?:POST|PUT)['"`].*(?:token|password|secret|key|credential|cookie|session)/gis,
    ],
  },
  {
    id: "NET-004",
    category: "Network Exfiltration",
    severity: Severity.MEDIUM,
    description: "Suspicious DNS/network lookup",
    patterns: [
      /dns\.(?:resolve|lookup)\s*\(/gi,
      /\.connect\s*\(\s*\d+/gi,
    ],
  },
  {
    id: "NET-005",
    category: "Network Exfiltration",
    severity: Severity.HIGH,
    description: "Ngrok or tunneling service URL detected",
    patterns: [
      /['"`]https?:\/\/[a-z0-9-]+\.(?:ngrok|serveo|localtunnel|loca\.lt)/gi,
    ],
  },
];
