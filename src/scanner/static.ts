import { ScannableFile } from "../repo/file-walker.js";
import { Finding, ScanReport, Severity } from "../report/types.js";
import { ALL_RULES } from "./rules/index.js";
import path from "node:path";

export function scanFiles(files: ScannableFile[], target: string): ScanReport {
  const findings: Finding[] = [];

  for (const file of files) {
    for (const rule of ALL_RULES) {
      if (rule.fileFilter && !rule.fileFilter.test(file.relativePath)) {
        continue;
      }

      for (const pattern of rule.patterns) {
        // Reset lastIndex for stateful regex
        pattern.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = pattern.exec(file.content)) !== null) {
          const line = getLineNumber(file.content, match.index);
          const snippet = getSnippet(file.content, line);

          findings.push({
            rule: rule.id,
            category: rule.category,
            severity: rule.severity,
            file: file.relativePath,
            line,
            description: rule.description,
            snippet,
          });

          // Prevent infinite loops on zero-length matches
          if (match[0].length === 0) {
            pattern.lastIndex++;
          }
        }
      }
    }
  }

  // Deduplicate findings (same rule + file + line)
  const unique = deduplicateFindings(findings);
  const riskScore = calculateRiskScore(unique);
  const verdict = getVerdict(riskScore);

  return {
    target,
    scanDate: new Date(),
    filesScanned: files.length,
    findings: unique,
    riskScore,
    verdict,
  };
}

function getLineNumber(content: string, index: number): number {
  return content.substring(0, index).split("\n").length;
}

function getSnippet(content: string, line: number): string {
  const lines = content.split("\n");
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 1);
  return lines
    .slice(start, end)
    .map((l, i) => {
      const lineNum = start + i + 1;
      const marker = lineNum === line ? ">" : " ";
      return `${marker} ${lineNum} | ${l}`;
    })
    .join("\n");
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.rule}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function calculateRiskScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;

  const weights: Record<Severity, number> = {
    [Severity.LOW]: 3,
    [Severity.MEDIUM]: 8,
    [Severity.HIGH]: 18,
    [Severity.CRITICAL]: 35,
  };

  let score = 0;
  for (const f of findings) {
    score += weights[f.severity];
  }

  return Math.min(100, score);
}

function getVerdict(score: number): "SAFE" | "SUSPICIOUS" | "DANGEROUS" {
  if (score <= 10) return "SAFE";
  if (score <= 40) return "SUSPICIOUS";
  return "DANGEROUS";
}
