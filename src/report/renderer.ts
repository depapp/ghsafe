import chalk from "chalk";
import boxen from "boxen";
import Table from "cli-table3";
import { ScanReport, Severity, Finding } from "./types.js";

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  [Severity.CRITICAL]: chalk.bgRed.white.bold,
  [Severity.HIGH]: chalk.red.bold,
  [Severity.MEDIUM]: chalk.yellow.bold,
  [Severity.LOW]: chalk.green,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  [Severity.CRITICAL]: "🔴",
  [Severity.HIGH]: "🟠",
  [Severity.MEDIUM]: "🟡",
  [Severity.LOW]: "🟢",
};

const VERDICT_STYLES: Record<string, (s: string) => string> = {
  SAFE: chalk.green.bold,
  SUSPICIOUS: chalk.yellow.bold,
  DANGEROUS: chalk.red.bold,
};

const VERDICT_ICONS: Record<string, string> = {
  SAFE: "✅",
  SUSPICIOUS: "⚠️",
  DANGEROUS: "🚨",
};

export function renderReport(report: ScanReport): void {
  console.log();

  // Header
  const riskBar = buildRiskBar(report.riskScore);
  const verdictColor = VERDICT_STYLES[report.verdict] ?? chalk.white;
  const verdictIcon = VERDICT_ICONS[report.verdict] ?? "";

  const headerContent = [
    `${chalk.bold("Target:")}     ${report.target}`,
    `${chalk.bold("Scanned:")}    ${report.filesScanned} files`,
    `${chalk.bold("Findings:")}   ${report.findings.length}`,
    `${chalk.bold("Risk Score:")} ${riskBar} ${report.riskScore}/100`,
    `${chalk.bold("Verdict:")}    ${verdictIcon} ${verdictColor(report.verdict)}`,
  ].join("\n");

  console.log(
    boxen(headerContent, {
      padding: 1,
      margin: { top: 0, bottom: 1, left: 0, right: 0 },
      borderColor: report.verdict === "SAFE" ? "green" : report.verdict === "SUSPICIOUS" ? "yellow" : "red",
      borderStyle: "round",
      title: "🛡️  ghsafe — Scan Report",
      titleAlignment: "center",
    })
  );

  if (report.findings.length === 0) {
    console.log(chalk.green.bold("  No suspicious patterns detected. This repository looks clean! ✨\n"));
    return;
  }

  // Summary by category
  renderCategorySummary(report.findings);

  // Findings table
  renderFindingsTable(report.findings);

  // Code previews for critical/high findings
  renderCodePreviews(report.findings);

  // AI Analysis
  if (report.aiAnalysis) {
    console.log(
      boxen(report.aiAnalysis, {
        padding: 1,
        margin: { top: 1, bottom: 1, left: 0, right: 0 },
        borderColor: "cyan",
        borderStyle: "round",
        title: "🤖 AI Analysis",
        titleAlignment: "center",
      })
    );
  }

  // Footer recommendation
  renderRecommendation(report);
}

function buildRiskBar(score: number): string {
  const filled = Math.round(score / 5);
  const empty = 20 - filled;
  const color =
    score <= 10 ? chalk.green : score <= 40 ? chalk.yellow : chalk.red;
  return color("█".repeat(filled)) + chalk.gray("░".repeat(empty));
}

function renderCategorySummary(findings: Finding[]): void {
  const categories = new Map<string, { count: number; maxSeverity: Severity }>();

  for (const f of findings) {
    const existing = categories.get(f.category);
    if (!existing) {
      categories.set(f.category, { count: 1, maxSeverity: f.severity });
    } else {
      existing.count++;
      if (severityWeight(f.severity) > severityWeight(existing.maxSeverity)) {
        existing.maxSeverity = f.severity;
      }
    }
  }

  console.log(chalk.bold.underline("  Category Summary\n"));
  for (const [cat, info] of categories) {
    const icon = SEVERITY_ICONS[info.maxSeverity];
    const color = SEVERITY_COLORS[info.maxSeverity];
    console.log(`  ${icon} ${color(cat)}: ${info.count} finding${info.count > 1 ? "s" : ""}`);
  }
  console.log();
}

function renderFindingsTable(findings: Finding[]): void {
  const sorted = [...findings].sort(
    (a, b) => severityWeight(b.severity) - severityWeight(a.severity)
  );

  const table = new Table({
    head: [
      chalk.bold("Sev"),
      chalk.bold("Rule"),
      chalk.bold("File"),
      chalk.bold("Line"),
      chalk.bold("Description"),
    ],
    style: { head: [], border: ["gray"] },
    colWidths: [10, 12, 30, 6, 50],
    wordWrap: true,
  });

  for (const f of sorted.slice(0, 30)) {
    const sevColor = SEVERITY_COLORS[f.severity];
    const icon = SEVERITY_ICONS[f.severity];
    table.push([
      `${icon} ${sevColor(f.severity)}`,
      chalk.dim(f.rule),
      chalk.cyan(truncate(f.file, 28)),
      String(f.line),
      f.description,
    ]);
  }

  console.log(table.toString());

  if (sorted.length > 30) {
    console.log(chalk.dim(`  ... and ${sorted.length - 30} more findings\n`));
  }
  console.log();
}

function renderCodePreviews(findings: Finding[]): void {
  const critical = findings.filter(
    (f) => f.severity === Severity.CRITICAL || f.severity === Severity.HIGH
  );

  if (critical.length === 0) return;

  console.log(chalk.bold.underline("  Code Previews (Critical/High)\n"));

  for (const f of critical.slice(0, 5)) {
    console.log(
      `  ${SEVERITY_ICONS[f.severity]} ${chalk.bold(f.file)}:${f.line} — ${chalk.dim(f.description)}`
    );
    const highlighted = f.snippet
      .split("\n")
      .map((line) => {
        if (line.startsWith(">")) {
          return chalk.bgRed.white(line);
        }
        return chalk.dim(line);
      })
      .join("\n");
    console.log(`${highlighted}\n`);
  }

  if (critical.length > 5) {
    console.log(chalk.dim(`  ... and ${critical.length - 5} more critical/high findings\n`));
  }
}

function renderRecommendation(report: ScanReport): void {
  let msg: string;
  if (report.verdict === "SAFE") {
    msg = chalk.green(
      "✅ This repository appears safe. Always review code before running it."
    );
  } else if (report.verdict === "SUSPICIOUS") {
    msg = chalk.yellow(
      "⚠️  Suspicious patterns detected. Review the findings above carefully before running this code.\n" +
        "   Consider running with --ai flag for deeper analysis."
    );
  } else {
    msg = chalk.red(
      "🚨 DANGER: This repository contains highly suspicious code patterns!\n" +
        "   DO NOT run this code without thorough manual review.\n" +
        "   This may be a phishing attempt or contain malware."
    );
  }
  console.log(
    boxen(msg, {
      padding: 1,
      margin: { top: 0, bottom: 1, left: 0, right: 0 },
      borderColor: report.verdict === "SAFE" ? "green" : report.verdict === "SUSPICIOUS" ? "yellow" : "red",
      borderStyle: "round",
      title: "💡 Recommendation",
      titleAlignment: "center",
    })
  );
}

function severityWeight(s: Severity): number {
  const w: Record<Severity, number> = {
    [Severity.LOW]: 1,
    [Severity.MEDIUM]: 2,
    [Severity.HIGH]: 3,
    [Severity.CRITICAL]: 4,
  };
  return w[s];
}

function truncate(s: string, max: number): string {
  return s.length > max ? "…" + s.slice(s.length - max + 1) : s;
}
