import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, promises as fs, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const sourceFont = path.join(root, "fonts/wqy-zenhei-sharp-0.9.45.ttf");
const outputFont = path.join(root, "public/fonts/wqy-zenhei-sharp-bitmap-subset.ttf");
const contentRoots = ["src/content", "src/config", "src/components", "src/pages"];
const textExtensions = new Set([".astro", ".phile", ".ts"]);
const textFile = path.join(mkdtempSync(path.join(os.tmpdir(), "entropic-font-")), "chars.txt");

if (!existsSync(sourceFont)) {
  throw new Error(`Missing source font: ${path.relative(root, sourceFont)}`);
}

const chars = await collectChars();
await fs.mkdir(path.dirname(outputFont), { recursive: true });
writeFileSync(textFile, chars, "utf8");

subsetFont();

function subsetFont(output = outputFont) {
  execFileSync(
    "pyftsubset",
    [
      sourceFont,
      `--output-file=${output}`,
      `--text-file=${textFile}`,
      "--layout-features=*",
      "--desubroutinize",
      "--drop-tables-=EBDT,EBLC,BDF",
      "--no-subset-tables+=EBDT,EBLC,BDF",
      "--passthrough-tables"
    ],
    { stdio: "inherit" }
  );
}

async function collectChars() {
  const files = (await Promise.all(contentRoots.map((dir) => listTextFiles(path.join(root, dir))))).flat();
  const chars = new Set(["　", "，", "。", "：", "；", "、", "？", "！", "（", "）", "《", "》", "「", "」"]);

  for (const file of files) {
    const text = await fs.readFile(file, "utf8");

    for (const char of text) {
      if (isCjkFontChar(char)) {
        chars.add(char);
      }
    }
  }

  return [...chars].join("");
}

async function listTextFiles(dir) {
  if (!existsSync(dir)) {
    return [];
  }

  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = await Promise.all(
    entries.map((entry) => {
      const entryPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        return listTextFiles(entryPath);
      }

      return entry.isFile() && textExtensions.has(path.extname(entry.name)) ? [entryPath] : [];
    })
  );

  return files.flat();
}

function isCjkFontChar(char) {
  return /[\u3000-\u303f\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef]/u.test(char);
}
