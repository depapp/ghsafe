import fs from "node:fs";
import path from "node:path";
import { SKIP_DIRS, SCAN_EXTENSIONS, MAX_FILE_SIZE } from "../utils/config.js";

export interface ScannableFile {
  filePath: string;
  relativePath: string;
  content: string;
}

export function walkFiles(repoPath: string): ScannableFile[] {
  const files: ScannableFile[] = [];
  walk(repoPath, repoPath, files);
  return files;
}

function walk(dir: string, root: string, result: ScannableFile[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".env") continue;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        walk(fullPath, root, result);
      }
      continue;
    }

    if (!entry.isFile()) continue;

    const ext = path.extname(entry.name).toLowerCase();
    // Also scan files with no extension (could be shell scripts)
    if (ext && !SCAN_EXTENSIONS.has(ext)) continue;

    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > MAX_FILE_SIZE) continue;
      if (stat.size === 0) continue;
    } catch {
      continue;
    }

    try {
      const content = fs.readFileSync(fullPath, "utf-8");
      // Skip binary files
      if (content.includes("\0")) continue;

      result.push({
        filePath: fullPath,
        relativePath: path.relative(root, fullPath),
        content,
      });
    } catch {
      continue;
    }
  }
}
