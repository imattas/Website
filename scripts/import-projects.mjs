import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import process from "node:process";

const owner = process.env.GITHUB_OWNER ?? "imattas";
const targetDir = path.resolve(process.cwd(), process.env.PROJECTS_TARGET ?? "src/content/philes/volume-1/projects");
const author = process.env.PROJECTS_AUTHOR ?? "Ian Mattas";

const repoFields = [
  "name",
  "description",
  "url",
  "isArchived",
  "isFork",
  "isPrivate",
  "pushedAt",
  "createdAt",
  "defaultBranchRef",
  "stargazerCount",
  "primaryLanguage"
].join(",");

async function main() {
  const repos = githubJson(["repo", "list", owner, "--limit", "200", "--json", repoFields, "--source"])
    .filter((repo) => !repo.isPrivate && !repo.isFork)
    .sort((left, right) => new Date(right.pushedAt).getTime() - new Date(left.pushedAt).getTime());

  await fs.rm(targetDir, { recursive: true, force: true });

  for (const [order, repo] of repos.entries()) {
    const slug = slugify(repo.name);
    const readme = readmeFor(repo.name);
    const body = projectBody(repo, readme);
    const output = addFrontmatter(body, {
      title: repo.isArchived ? `${repo.name} (archived)` : repo.name,
      date: formatDate(repo.pushedAt ?? repo.createdAt ?? new Date()),
      slug,
      order
    });
    const targetPath = path.join(targetDir, slug, "index.mdx");

    await fs.mkdir(path.dirname(targetPath), { recursive: true });
    await fs.writeFile(targetPath, output, "utf8");
  }

  console.log(`Imported ${repos.length} GitHub projects from ${owner} into ${targetDir}`);
}

function githubJson(args) {
  return JSON.parse(execFileSync("gh", args, { encoding: "utf8" }));
}

function readmeFor(repoName) {
  try {
    return execFileSync("gh", ["api", "-H", "Accept: application/vnd.github.raw", `repos/${owner}/${repoName}/readme`], {
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024
    });
  } catch {
    return "";
  }
}

function projectBody(repo, readme) {
  const description = repo.description?.trim() || "No repository description provided.";
  const language = repo.primaryLanguage?.name ?? "Unspecified";
  const status = repo.isArchived ? "archived" : "active";
  const stars = String(repo.stargazerCount ?? 0);
  const cleanReadme = rewriteRelativeMarkdownUrls(stripFrontmatter(readme).trim(), repo);

  return `--[ repository ]------------------------------------------------------------

    URL      : ${repo.url}
    Language : ${language}
    Status   : ${status}
    Stars    : ${stars}
    Updated  : ${formatDate(repo.pushedAt ?? repo.createdAt ?? new Date())}

${description}

---

${cleanReadme || "README not available for this repository."}
`;
}

function rewriteRelativeMarkdownUrls(markdown, repo) {
  const branch = repo.defaultBranchRef?.name ?? "main";

  return markdown.replace(/(!?)\[([^\]]*)]\(([^)\s]+)(\s+["'][^"']*["'])?\)/g, (match, bang, label, href, title = "") => {
    if (!isRelativeRepoUrl(href)) {
      return match;
    }

    const base =
      bang === "!"
        ? `https://raw.githubusercontent.com/${owner}/${repo.name}/${branch}/`
        : `https://github.com/${owner}/${repo.name}/blob/${branch}/`;
    const normalizedHref = href.startsWith("/") ? href.slice(1) : href;
    const resolved = new URL(normalizedHref, base).toString();

    return `${bang}[${label}](${resolved}${title})`;
  });
}

function isRelativeRepoUrl(href) {
  return !/^(?:[a-z][a-z0-9+.-]*:|#)/i.test(href);
}

function addFrontmatter(body, data) {
  return `---
title: ${JSON.stringify(data.title)}
date: ${data.date}
author: ${JSON.stringify(author)}
slug: ${JSON.stringify(data.slug)}
order: ${data.order}
contentFormat: "markdown"
---

${body.trim()}
`;
}

function stripFrontmatter(source) {
  if (!source.startsWith("---\n")) {
    return source;
  }

  const end = source.indexOf("\n---\n", 4);
  return end === -1 ? source : source.slice(end + 5);
}

function slugify(input) {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
}

function formatDate(input) {
  return new Date(input).toISOString().slice(0, 10);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
