export enum Severity {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}

export interface Finding {
  rule: string;
  category: string;
  severity: Severity;
  file: string;
  line: number;
  description: string;
  snippet: string;
}

export interface ScanReport {
  target: string;
  scanDate: Date;
  filesScanned: number;
  findings: Finding[];
  riskScore: number;
  verdict: "SAFE" | "SUSPICIOUS" | "DANGEROUS";
  aiAnalysis?: string;
}

export interface Rule {
  id: string;
  category: string;
  severity: Severity;
  description: string;
  patterns: RegExp[];
  fileFilter?: RegExp;
}
