import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { loadRepo, cleanupTemp } from "./repo/loader.js";
import { walkFiles } from "./repo/file-walker.js";
import { scanFiles } from "./scanner/static.js";
import { analyzeWithAI } from "./scanner/ai.js";
import { renderReport } from "./report/renderer.js";

const program = new Command();

program
  .name("ghsafe")
  .description(
    "🛡️  GitHub Repository Security Analyzer — Scan repos for phishing, malware, and suspicious code"
  )
  .version("1.0.0");

program
  .command("scan")
  .description("Scan a GitHub repository or local directory for suspicious code")
  .argument("<target>", "GitHub repository URL or local directory path")
  .option("--ai", "Enable AI-powered deep analysis (requires OPENAI_API_KEY)")
  .option("--json", "Output results as JSON")
  .action(async (target: string, opts: { ai?: boolean; json?: boolean }) => {
    console.log(
      chalk.bold("\n🛡️  ghsafe — GitHub Repository Security Analyzer\n")
    );

    // Load repository
    const spinner = ora("Loading repository...").start();
    let repoPath: string;
    let isTemp = false;

    try {
      const result = await loadRepo(target);
      repoPath = result.repoPath;
      isTemp = result.isTemp;
      spinner.succeed(
        isTemp
          ? `Cloned repository to temporary directory`
          : `Using local directory: ${repoPath}`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      spinner.fail(`Failed to load repository: ${msg}`);
      process.exit(1);
    }

    try {
      // Walk files
      const fileSpinner = ora("Scanning files...").start();
      const files = walkFiles(repoPath);
      fileSpinner.succeed(`Found ${files.length} files to analyze`);

      // Static scan
      const scanSpinner = ora("Analyzing code for suspicious patterns...").start();
      const report = scanFiles(files, target);
      scanSpinner.succeed(
        `Analysis complete — ${report.findings.length} findings`
      );

      // AI analysis (optional)
      if (opts.ai) {
        const apiKey = process.env.OPENAI_API_KEY;
        if (!apiKey) {
          ora().warn(
            chalk.yellow(
              "OPENAI_API_KEY not set. Skipping AI analysis. Set it with: export OPENAI_API_KEY=your-key"
            )
          );
        } else if (report.findings.length === 0) {
          ora().info("No findings to analyze with AI.");
        } else {
          const aiSpinner = ora("Running AI-powered deep analysis...").start();
          try {
            report.aiAnalysis = await analyzeWithAI(report.findings, apiKey);
            aiSpinner.succeed("AI analysis complete");
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            aiSpinner.fail(`AI analysis failed: ${msg}`);
          }
        }
      }

      // Output
      if (opts.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        renderReport(report);
      }

      // Exit with appropriate code
      process.exit(report.verdict === "DANGEROUS" ? 2 : report.verdict === "SUSPICIOUS" ? 1 : 0);
    } finally {
      if (isTemp) {
        cleanupTemp(repoPath);
      }
    }
  });

// Default: show help if no command
program.action(() => {
  program.help();
});

program.parse();
