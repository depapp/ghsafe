import fs from "node:fs";
import path from "node:path";
import { simpleGit } from "simple-git";
import os from "node:os";

const GITHUB_URL_RE =
  /^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+(\.git)?$/;

export function isGitHubUrl(input: string): boolean {
  return GITHUB_URL_RE.test(input.split("#")[0].split("?")[0]);
}

export async function loadRepo(
  input: string
): Promise<{ repoPath: string; isTemp: boolean }> {
  if (isGitHubUrl(input)) {
    const tmpDir = path.join(
      os.tmpdir(),
      `ghsafe-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    );
    const git = simpleGit();
    await git.clone(input, tmpDir, ["--depth", "1"]);
    return { repoPath: tmpDir, isTemp: true };
  }

  const resolved = path.resolve(input);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Path does not exist: ${resolved}`);
  }
  if (!fs.statSync(resolved).isDirectory()) {
    throw new Error(`Path is not a directory: ${resolved}`);
  }
  return { repoPath: resolved, isTemp: false };
}

export function cleanupTemp(repoPath: string): void {
  try {
    fs.rmSync(repoPath, { recursive: true, force: true });
  } catch {
    // ignore cleanup errors
  }
}
