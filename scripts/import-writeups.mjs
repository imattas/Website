import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import process from "node:process";

const sourceDir = path.resolve(process.cwd(), process.env.WRITEUPS_SOURCE ?? "../Writeups");
const targetDir = path.resolve(process.cwd(), process.env.WRITEUPS_TARGET ?? "src/content/philes/volume-2/writeups");
const author = process.env.WRITEUPS_AUTHOR ?? "Ian Mattas";

async function main() {
  const stat = await fs.stat(sourceDir).catch(() => undefined);

  if (!stat?.isDirectory()) {
    throw new Error(`Writeups source directory not found: ${sourceDir}`);
  }

  const sourceFiles = await listMdx(sourceDir);
  const orderedFiles = await orderFiles(sourceFiles);
  const ctfTitles = await ctfTitleMap(sourceFiles);
  const usedSlugs = new Set();

  await fs.rm(targetDir, { recursive: true, force: true });

  for (const [order, sourcePath] of orderedFiles.entries()) {
    const source = await fs.readFile(path.join(sourceDir, sourcePath), "utf8");
    const slug = uniqueSlug(slugFromPath(sourcePath), usedSlugs);
    const output = addFrontmatter(source, {
      title: titleFromMdx(sourcePath, source),
      date: dateFromMdx(source) ?? gitDate(sourcePath),
      slug,
      order,
      ...writeupMetadata(sourcePath, ctfTitles)
    });
    const targetPath = path.join(targetDir, outputPathFor(sourcePath, slug));

    await fs.mkdir(path.dirname(targetPath), { recursive: true });
    await fs.writeFile(targetPath, output, "utf8");
  }

  console.log(`Imported ${orderedFiles.length} MDX writeups from ${sourceDir} into ${targetDir}`);
}

async function listMdx(dir, base = dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    if (entry.name === ".git") {
      continue;
    }

    const entryPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await listMdx(entryPath, base)));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith(".mdx")) {
      files.push(toPosix(path.relative(base, entryPath)));
    }
  }

  return files;
}

async function orderFiles(files) {
  const remaining = new Set(files);
  const ordered = [];

  take("README.mdx");
  take("EXAMPLE_WRITEUP.mdx");

  for (const ctfDir of await ctfOrder()) {
    const index = `${ctfDir}/README.mdx`;
    take(index);

    for (const linked of await linkedMdxFiles(index)) {
      take(path.posix.normalize(path.posix.join(ctfDir, linked)));
    }
  }

  ordered.push(...[...remaining].sort((left, right) => left.localeCompare(right, "en", { numeric: true })));
  return ordered;

  function take(sourcePath) {
    if (!remaining.has(sourcePath)) {
      return;
    }

    remaining.delete(sourcePath);
    ordered.push(sourcePath);
  }
}

async function ctfOrder() {
  const root = await readSource("README.mdx");
  const dirs = [];
  const pattern = /\]\(\.\/([^)]*?)\/README\.mdx(?:#[^)]*)?\)/g;

  for (const match of root.matchAll(pattern)) {
    dirs.push(decodeURIComponent(match[1]));
  }

  return dirs;
}

async function linkedMdxFiles(sourcePath) {
  const source = await readSource(sourcePath).catch(() => "");
  const files = [];
  const pattern = /\]\(\.\/([^)]*?\.mdx)(?:#[^)]*)?\)/g;

  for (const match of source.matchAll(pattern)) {
    files.push(decodeURIComponent(match[1]));
  }

  return files;
}

async function readSource(sourcePath) {
  return fs.readFile(path.join(sourceDir, sourcePath), "utf8");
}

async function ctfTitleMap(files) {
  const titles = new Map();

  for (const sourcePath of files) {
    if (!sourcePath.endsWith("/README.mdx")) {
      continue;
    }

    const ctfDir = sourcePath.slice(0, -"/README.mdx".length);
    const source = await readSource(sourcePath);
    titles.set(ctfDir, stripWriteupsSuffix(titleFromMdx(sourcePath, source)));
  }

  return titles;
}

function writeupMetadata(sourcePath, ctfTitles) {
  if (sourcePath === "README.mdx") {
    return { writeupKind: "root" };
  }

  if (sourcePath === "EXAMPLE_WRITEUP.mdx") {
    return { writeupKind: "template" };
  }

  const parts = sourcePath.split("/");

  if (parts.length < 2) {
    return {};
  }

  const ctfDir = parts[0];
  const ctfTitle = ctfTitles.get(ctfDir) ?? ctfDir;
  const ctfSlug = pathSegmentSlug(ctfDir);
  const writeupKind = parts.at(-1) === "README.mdx" ? "ctf" : "challenge";

  return {
    writeupKind,
    ctfSlug,
    ctfTitle
  };
}

function addFrontmatter(source, data) {
  const body = stripFrontmatter(source).trim();
  const frontmatter = [
    `title: ${JSON.stringify(data.title)}`,
    `date: ${data.date}`,
    `author: ${JSON.stringify(author)}`,
    `slug: ${JSON.stringify(data.slug)}`,
    `order: ${data.order}`
  ];

  if (data.writeupKind) {
    frontmatter.push(`writeupKind: ${JSON.stringify(data.writeupKind)}`);
  }

  if (data.ctfSlug) {
    frontmatter.push(`ctfSlug: ${JSON.stringify(data.ctfSlug)}`);
  }

  if (data.ctfTitle) {
    frontmatter.push(`ctfTitle: ${JSON.stringify(data.ctfTitle)}`);
  }

  return `---
${frontmatter.join("\n")}
---

${body}
`;
}

function stripFrontmatter(source) {
  if (!source.startsWith("---\n")) {
    return source;
  }

  const end = source.indexOf("\n---\n", 4);
  return end === -1 ? source : source.slice(end + 5);
}

function titleFromMdx(sourcePath, source) {
  const heading = source.match(/^#\s+(.+?)\s*$/m)?.[1];
  const candidate = heading ?? path.posix.basename(sourcePath, path.posix.extname(sourcePath));

  return candidate
    .replace(/\[([^\]]+)]\([^)]+\)/g, "$1")
    .replace(/[`*_~]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function dateFromMdx(source) {
  const match = source.match(/^\s*>\s*\*\*Date:\*\*\s*(.+?)\s*$/m);

  if (!match) {
    return undefined;
  }

  const date = new Date(match[1]);
  return Number.isNaN(date.getTime()) ? undefined : formatDate(date);
}

function gitDate(sourcePath) {
  const candidates = [sourcePath, sourcePath.replace(/\.mdx$/, ".md")];

  for (const candidate of candidates) {
    try {
      const date = execFileSync("git", ["log", "-1", "--format=%cs", "--", candidate], {
        cwd: sourceDir,
        encoding: "utf8"
      }).trim();

      if (date) {
        return date;
      }
    } catch {
      // Try the next path before falling back to today's date.
    }
  }

  return formatDate(new Date());
}

function slugFromPath(sourcePath) {
  const withoutExtension = sourcePath.slice(0, -path.posix.extname(sourcePath).length);
  const normalized =
    withoutExtension === "README"
      ? "writeups-index"
      : withoutExtension === "EXAMPLE_WRITEUP"
        ? "writeup-template"
        : withoutExtension.endsWith("/README")
          ? withoutExtension.slice(0, -"/README".length)
          : withoutExtension;

  return normalized
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
}

function outputPathFor(sourcePath, slug) {
  if (sourcePath === "README.mdx") {
    return "index.mdx";
  }

  if (sourcePath === "EXAMPLE_WRITEUP.mdx") {
    return "template/index.mdx";
  }

  const parts = sourcePath.split("/");
  const filename = parts.at(-1) ?? sourcePath;
  const parentParts = parts.slice(0, -1).map(pathSegmentSlug);

  if (filename === "README.mdx") {
    return path.join(...parentParts, "index.mdx");
  }

  const challengeFolder = pathSegmentSlug(path.posix.basename(filename, path.posix.extname(filename)));
  return path.join(...parentParts, challengeFolder || slug, "index.mdx");
}

function pathSegmentSlug(input) {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
}

function stripWriteupsSuffix(input) {
  return input.replace(/\s+Writeups$/i, "");
}

function uniqueSlug(baseSlug, usedSlugs) {
  let slug = baseSlug || "writeup";
  let suffix = 2;

  while (usedSlugs.has(slug)) {
    slug = `${baseSlug}-${suffix}`;
    suffix += 1;
  }

  usedSlugs.add(slug);
  return slug;
}

function formatDate(input) {
  return new Date(input).toISOString().slice(0, 10);
}

function toPosix(input) {
  return input.split(path.sep).join("/");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
