# 🛡️ ghsafe — GitHub Repository Security Analyzer

> **Don't run that repo!** Scan GitHub repositories for phishing, malware, and suspicious code before you clone and run them.

![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## 🎯 Why ghsafe?

A developer friend received a job offer on LinkedIn from someone pretending to be an HR from a well-known tech company. The "interview process" required cloning and running a GitHub repository — a seemingly normal coding exercise. Luckily, my friend reviewed the code first and found **hidden data exfiltration, environment variable theft, and obfuscated payloads** buried inside.

Not everyone is that careful. **ghsafe** is a CLI tool that scans any GitHub repository for malicious patterns **before you run it**, helping protect developers from:

- 🎣 **Phishing repos** disguised as job interviews or coding tests
- 💀 **Malware** hidden in postinstall scripts
- 🔑 **Credential theft** targeting SSH keys, API tokens, and browser data
- ⛏️ **Crypto miners** embedded in seemingly normal projects
- 🕳️ **Backdoors** and persistence mechanisms

## 📦 Installation

```bash
# Clone and build
git clone https://github.com/YOUR_USERNAME/ghsafe.git
cd ghsafe
npm install
npm run build

# Link globally (optional)
npm link
```

## 🚀 Usage

### Scan a GitHub Repository

```bash
ghsafe scan https://github.com/user/suspicious-repo
```

### Scan a Local Directory

```bash
ghsafe scan ./path/to/project
```

### Enable AI-Powered Analysis

```bash
export OPENAI_API_KEY=your-key
ghsafe scan https://github.com/user/repo --ai
```

### JSON Output (for CI/CD)

```bash
ghsafe scan ./project --json
```

## 🔍 What It Detects

| Category | Examples | Severity |
|---|---|---|
| **Network Exfiltration** | Webhook URLs, raw IP connections, tunneling services | 🟠 HIGH |
| **Data Exfiltration** | SSH key theft, env var collection, browser data access, crypto wallets | 🔴 CRITICAL |
| **Code Obfuscation** | `eval()`, `Function()`, Base64/hex payloads, `String.fromCharCode` | 🟠 HIGH |
| **Dangerous Execution** | `child_process`, shell commands, download-and-exec pipelines | 🔴 CRITICAL |
| **Crypto Mining** | Mining pool connections, known miner libraries, wallet addresses | 🔴 CRITICAL |
| **Persistence** | Crontab manipulation, shell profile modification, startup scripts | 🟠 HIGH |
| **Suspicious Install Scripts** | `postinstall` hooks that run code, download scripts | 🔴 CRITICAL |

## 📊 Output

ghsafe produces a rich terminal report with:

- **Risk Score** (0-100) with visual bar
- **Verdict**: ✅ SAFE / ⚠️ SUSPICIOUS / 🚨 DANGEROUS
- **Category Summary** with severity-coded findings
- **Findings Table** with file, line number, and description
- **Code Previews** showing suspicious lines in context
- **AI Analysis** (optional) with threat assessment and recommendations

### Example Output

```
╭────────── 🛡️  ghsafe — Scan Report ──────────╮
│                                              │
│   Target:     https://github.com/user/repo   │
│   Scanned:    42 files                       │
│   Findings:   13                             │
│   Risk Score: ████████████████████ 100/100   │
│   Verdict:    🚨 DANGEROUS                   │
│                                              │
╰──────────────────────────────────────────────╯

  Category Summary

  🟠 Network Exfiltration: 2 findings
  🔴 Data Exfiltration: 3 findings
  🟠 Code Obfuscation: 2 findings
  🔴 Dangerous Execution: 3 findings
  🔴 Crypto Mining: 1 finding
  🟠 Persistence: 1 finding
  🔴 Suspicious Install Scripts: 1 finding
```

## 🤖 AI-Powered Analysis

When you enable the `--ai` flag, ghsafe sends a summary of the findings to OpenAI's GPT-4o-mini for deeper contextual analysis. This helps:

- Distinguish false positives from real threats
- Understand the intent behind suspicious patterns
- Get actionable recommendations

**Note:** AI analysis is optional and requires an `OPENAI_API_KEY`. The basic static scan works without any API keys.

## 🏗️ Architecture

```
src/
├── index.ts              # CLI entry point (Commander.js)
├── scanner/
│   ├── static.ts          # Static pattern scanner engine
│   ├── ai.ts              # AI-powered analysis (OpenAI)
│   └── rules/
│       ├── network.ts     # Network exfiltration rules
│       ├── obfuscation.ts # Code obfuscation rules
│       ├── exfiltration.ts# Data theft rules
│       ├── execution.ts   # Dangerous execution rules
│       ├── crypto.ts      # Crypto mining rules
│       ├── persistence.ts # Persistence mechanism rules
│       ├── install-scripts.ts # Suspicious install scripts
│       └── index.ts       # Rule registry
├── repo/
│   ├── loader.ts          # GitHub URL cloning / local path loading
│   └── file-walker.ts     # Directory traversal with filtering
├── report/
│   ├── renderer.ts        # Rich terminal output
│   └── types.ts           # TypeScript type definitions
└── utils/
    └── config.ts          # Configuration constants
```

## 🔧 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Repository is safe |
| `1` | Suspicious patterns found |
| `2` | Dangerous patterns detected |

This makes ghsafe easy to integrate into CI/CD pipelines.

## 🛠️ Built With

- **TypeScript** — Type-safe development
- **Commander.js** — CLI framework
- **chalk, ora, boxen, cli-table3** — Rich terminal UI
- **simple-git** — Git operations
- **OpenAI SDK** — AI-powered analysis
- **tsup** — Fast TypeScript bundler
- **GitHub Copilot CLI** — AI-assisted development throughout

## 📄 License

MIT — see [LICENSE](LICENSE)

---

*Built with ❤️ and 🛡️ to protect developers from malicious repositories.*
