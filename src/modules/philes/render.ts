import { textmodeConfig } from "../../config";
import { renderAnsiText } from "../textmode/ansi/render";
import { escapeHtml, link, textHtml } from "../textmode/core/html";
import { cellWidth, padCells, truncateCells, wrapWordsCells } from "../textmode/core/layout";
import { lifeFrameHeight, lifeFrameHtml } from "../textmode/life/art";
import type { Phile } from "./model";

const titleWidth = textmodeConfig.articleArtIndent - textmodeConfig.textIndent;
const indexInnerWidth = textmodeConfig.bodyWidth - 2;
const indexContentWidth = indexInnerWidth - 2;

export type PhileHeader = {
  metaHtml: string;
  sideHtml: string;
  lineCount: number;
  metaLineCount: number;
  titleLineCount: number;
};

export type PhileBodyBlock = {
  kind: "text" | "code" | "image";
  html: string;
};

export function renderPhileHeader(phile: Phile): PhileHeader {
  const titleLines = wrapWordsCells(phile.data.title, titleWidth);
  const metaLines = [...titleLines, `~ ${phile.data.author}`];

  return {
    metaHtml: metaLines.map(textHtml).join("\n"),
    sideHtml: lifeFrameHtml(),
    lineCount: lifeFrameHeight,
    metaLineCount: metaLines.length,
    titleLineCount: titleLines.length
  };
}

export function renderPhileBodyBlocks(phile: Phile): PhileBodyBlock[] {
  const markdown = isMarkdownPhile(phile);
  const body = markdown ? removeDuplicateTitleHeading(phile, phile.body ?? "") : (phile.body ?? "");
  const blocks = markdown ? splitMarkdownBlocks(body) : splitBodyBlocks(body);

  return blocks.map((block) => {
    if (block.kind === "image") {
      return {
        kind: "image",
        html: renderImage(block.src, block.alt)
      };
    }

    if (block.kind === "code") {
      return {
        kind: "code",
        html: renderCodeBlock(block.code, block.language)
      };
    }

    return {
      kind: "text",
      html: `${renderTextBlock(phile, block.text)}\n`
    };
  });
}

export function renderPhileFooterPre(phile: Phile): string {
  return `\n\nret ${link(phile.route.volumeHref, `<volume_${phile.route.volume}>`)}\n`;
}

export function renderPhileChildIndexPre(parent: Phile, children: Phile[]): string {
  const title = parent.data.ctfTitle ?? stripWriteupsSuffix(parent.data.title);
  const labelWidth = Math.max(3, ...children.map((_, index) => cellWidth(childLabel(index))));
  const lines = [
    `┌${"─".repeat(indexInnerWidth)}┐`,
    frameLine(title),
    frameLine("WRITEUPS"),
    frameLine(""),
    ...(children.length > 0
      ? children.map((child, index) => renderChildLine(parent, child, index, labelWidth))
      : [frameLine("no writeups imported for this CTF")]),
    frameLine(""),
    `└${"─".repeat(indexInnerWidth)}┘`
  ];

  return `${lines.join("\n")}\n`;
}

type ParsedBodyBlock =
  | { kind: "text"; text: string }
  | { kind: "code"; code: string; language?: string }
  | { kind: "image"; src: string; alt: string };

function splitBodyBlocks(input: string): ParsedBodyBlock[] {
  const blocks: ParsedBodyBlock[] = [];
  const textLines: string[] = [];

  for (const line of input.split("\n")) {
    const image = parseImageLine(line);

    if (!image) {
      textLines.push(line);
      continue;
    }

    flushTextBlock(blocks, textLines);
    blocks.push({ kind: "image", ...image });
  }

  flushTextBlock(blocks, textLines);
  return blocks;
}

function flushTextBlock(blocks: ParsedBodyBlock[], textLines: string[]): void {
  const text = textLines.join("\n").trim();

  if (text.length > 0) {
    blocks.push({ kind: "text", text });
  }

  textLines.length = 0;
}

function splitMarkdownBlocks(input: string): ParsedBodyBlock[] {
  const blocks: ParsedBodyBlock[] = [];
  const textLines: string[] = [];
  const codeLines: string[] = [];
  let codeLanguage: string | undefined;
  let fenceMarker: string | undefined;

  for (const line of input.replace(/\r\n/g, "\n").split("\n")) {
    const fence = line.match(/^\s*(```+|~~~+)\s*([^\s`]*)?.*$/);

    if (fence) {
      if (fenceMarker) {
        blocks.push({ kind: "code", code: codeLines.join("\n"), language: codeLanguage });
        codeLines.length = 0;
        codeLanguage = undefined;
        fenceMarker = undefined;
        continue;
      }

      flushTextBlock(blocks, textLines);
      fenceMarker = fence[1];
      codeLanguage = fence[2] || undefined;
      continue;
    }

    if (fenceMarker) {
      codeLines.push(line);
      continue;
    }

    const image = parseImageLine(line);

    if (image) {
      flushTextBlock(blocks, textLines);
      blocks.push({ kind: "image", ...image });
      continue;
    }

    textLines.push(line);
  }

  if (fenceMarker) {
    blocks.push({ kind: "code", code: codeLines.join("\n"), language: codeLanguage });
  }

  flushTextBlock(blocks, textLines);
  return blocks;
}

function renderTextBlock(phile: Phile, text: string): string {
  if (!isMarkdownPhile(phile)) {
    return renderAnsiText(text, textmodeConfig.bodyWidth);
  }

  return renderAnsiText(formatMarkdownText(text, phile), textmodeConfig.bodyWidth, { wordWrap: true });
}

function formatMarkdownText(input: string, phile: Phile): string {
  const lines = input.replace(/\r\n/g, "\n").split("\n");
  const output: string[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    if (isTableStart(lines, index)) {
      const tableLines: string[] = [];

      while (index < lines.length && isTableLine(lines[index])) {
        tableLines.push(lines[index]);
        index += 1;
      }

      index -= 1;
      pushBlankBefore(output);
      output.push(...formatMarkdownTable(tableLines));
      output.push("");
      continue;
    }

    const formatted = formatMarkdownLine(lines[index], phile);

    if (formatted === undefined) {
      continue;
    }

    if (formatted.length > 0 && isHeadingLine(lines[index])) {
      pushBlankBefore(output);
    }

    output.push(formatted);
  }

  return trimBlankLines(output).join("\n");
}

function formatMarkdownLine(line: string, phile: Phile): string | undefined {
  const heading = line.match(/^(#{1,6})\s+(.+?)\s*#*\s*$/);

  if (heading) {
    const level = heading[1].length;
    const title = stripInlineMarkdown(heading[2]);

    if (level === 1 && normalizeTitle(title) === normalizeTitle(phile.data.title)) {
      return undefined;
    }

    if (level === 1 || level === 2) {
      return marker("C", `--[ ${title} ]--`);
    }

    if (level === 3) {
      return marker("Y", `:: ${title}`);
    }

    return marker("M", `> ${title}`);
  }

  if (/^\s*-{3,}\s*$/.test(line)) {
    return marker("K", "─".repeat(textmodeConfig.bodyWidth));
  }

  const quote = line.match(/^\s*>\s?(.*)$/);

  if (quote) {
    return `${marker("K", "│")} ${inlineMarkdownToAnsi(quote[1] ?? "")}`;
  }

  const unordered = line.match(/^(\s*)[-*+]\s+(.+)$/);

  if (unordered) {
    return `${listIndent(unordered[1])}- ${inlineMarkdownToAnsi(unordered[2])}`;
  }

  const ordered = line.match(/^(\s*)(\d+)\.\s+(.+)$/);

  if (ordered) {
    return `${listIndent(ordered[1])}${ordered[2]}. ${inlineMarkdownToAnsi(ordered[3])}`;
  }

  return inlineMarkdownToAnsi(line);
}

function isHeadingLine(line: string): boolean {
  return /^(#{1,6})\s+/.test(line);
}

function listIndent(input: string | undefined): string {
  return "  ".repeat(Math.min(4, Math.floor((input?.length ?? 0) / 2)));
}

function isTableStart(lines: string[], index: number): boolean {
  return isTableLine(lines[index]) && isTableSeparator(lines[index + 1]);
}

function isTableLine(line: string | undefined): boolean {
  return Boolean(line?.includes("|") && line.trim().length > 0);
}

function isTableSeparator(line: string | undefined): boolean {
  return Boolean(line?.match(/^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/));
}

function formatMarkdownTable(lines: string[]): string[] {
  const rows = lines
    .filter((line) => !isTableSeparator(line))
    .map(parseTableRow)
    .filter((row) => row.length > 0);
  const columnCount = Math.max(0, ...rows.map((row) => row.length));
  const widths = Array.from({ length: columnCount }, (_, column) =>
    Math.min(28, Math.max(3, ...rows.map((row) => cellWidth(row[column] ?? ""))))
  );

  return rows.map((row, rowIndex) => {
    const cells = widths.map((width, column) => padCells(truncateCells(row[column] ?? "", width), width));
    const line = cells.join("  ");
    return rowIndex === 0 ? marker("W", line) : line;
  });
}

function parseTableRow(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => stripInlineMarkdown(cell.trim()));
}

function inlineMarkdownToAnsi(input: string): string {
  const pattern =
    /(`+)([^`]+?)\1|\*\*\[([^\]]+)]\(([^)]+)\)\*\*|__\[([^\]]+)]\(([^)]+)\)__|\[([^\]]+)]\(([^)]+)\)|\*\*([^*]+)\*\*|__([^_]+)__|\*([^*]+)\*|_([^_]+)_/g;
  let output = "";
  let cursor = 0;

  for (const match of input.matchAll(pattern)) {
    const index = match.index ?? 0;
    output += escapeAnsiLiteral(input.slice(cursor, index));

    if (match[2] !== undefined) {
      output += marker("Y", match[2]);
    } else if (match[3] !== undefined && match[4] !== undefined) {
      output += markdownLinkToAnsi(match[3], match[4]);
    } else if (match[5] !== undefined && match[6] !== undefined) {
      output += markdownLinkToAnsi(match[5], match[6]);
    } else if (match[7] !== undefined && match[8] !== undefined) {
      output += markdownLinkToAnsi(match[7], match[8]);
    } else if (match[9] !== undefined || match[10] !== undefined) {
      output += marker("W", match[9] ?? match[10] ?? "");
    } else {
      output += escapeAnsiLiteral(match[11] ?? match[12] ?? "");
    }

    cursor = index + match[0].length;
  }

  return `${output}${escapeAnsiLiteral(input.slice(cursor))}`;
}

function markdownLinkToAnsi(label: string, href: string): string {
  const cleanLabel = stripInlineMarkdown(label);

  if (/^https?:\/\//i.test(href)) {
    return `${escapeAnsiLiteral(cleanLabel)} ${escapeAnsiLiteral(href)}`;
  }

  return marker("C", cleanLabel);
}

function stripInlineMarkdown(input: string): string {
  return input
    .replace(/\[([^\]]+)]\([^)]+\)/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/__([^_]+)__/g, "$1")
    .replace(/\*([^*]+)\*/g, "$1")
    .replace(/_([^_]+)_/g, "$1")
    .replace(/<[^>]+>/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function marker(role: string, text: string): string {
  return `#[${role}|${escapeAnsiMarkerText(text)}]`;
}

function escapeAnsiLiteral(input: string): string {
  return input.replace(/#\[/g, "\\#[");
}

function escapeAnsiMarkerText(input: string): string {
  return input.replace(/([#[\]|\\])/g, "\\$1");
}

function trimBlankLines(lines: string[]): string[] {
  const trimmed = [...lines];

  while (trimmed[0] === "") {
    trimmed.shift();
  }

  while (trimmed.at(-1) === "") {
    trimmed.pop();
  }

  return trimmed;
}

function pushBlankBefore(lines: string[]): void {
  if (lines.length > 0 && lines.at(-1) !== "") {
    lines.push("");
  }
}

function removeDuplicateTitleHeading(phile: Phile, input: string): string {
  const lines = input.replace(/\r\n/g, "\n").split("\n");
  const firstContentIndex = lines.findIndex((line) => line.trim().length > 0);

  if (firstContentIndex === -1) {
    return input;
  }

  const heading = lines[firstContentIndex].match(/^#\s+(.+?)\s*#*\s*$/);

  if (!heading || normalizeTitle(stripInlineMarkdown(heading[1])) !== normalizeTitle(phile.data.title)) {
    return input;
  }

  lines.splice(firstContentIndex, 1);
  return lines.join("\n");
}

function normalizeTitle(input: string): string {
  return input.replace(/[—–]/g, "-").replace(/\s+/g, " ").trim().toLowerCase();
}

function isMarkdownPhile(phile: Phile): boolean {
  return phile.data.contentFormat === "markdown" || phile.data.writeupKind !== undefined;
}

function parseImageLine(line: string): { src: string; alt: string } | undefined {
  const markdownImage = line.match(/^\s*!\[([^\]]*)\]\((\S+?)(?:\s+["'][^"']*["'])?\)\s*$/);

  if (markdownImage) {
    return {
      alt: markdownImage[1],
      src: markdownImage[2]
    };
  }

  const htmlImage = line.match(/^\s*<img\b([^>]*)>\s*$/i);

  if (!htmlImage) {
    return undefined;
  }

  const attrs = htmlImage[1];
  const src = readHtmlAttr(attrs, "src");

  if (!src) {
    return undefined;
  }

  return {
    src,
    alt: readHtmlAttr(attrs, "alt") ?? ""
  };
}

function readHtmlAttr(attrs: string, name: string): string | undefined {
  const match = attrs.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return match?.[1] ?? match?.[2] ?? match?.[3];
}

function renderImage(src: string, alt: string): string {
  const safeSrc = escapeHtml(src);
  const safeAlt = escapeHtml(alt);
  const caption = alt.trim().length > 0 ? `\n<figcaption>${textHtml(alt)}</figcaption>` : "";

  return `<figure class="phile-image"><button class="phile-image-trigger" type="button" data-lightbox-image aria-label="Open image preview"><img src="${safeSrc}" alt="${safeAlt}" loading="lazy" decoding="async" /></button>${caption}</figure>`;
}

function renderCodeBlock(code: string, language: string | undefined): string {
  const label = language ? `${textHtml(`-- ${language} --`)}\n` : "";
  const source = code.replace(/\s+$/u, "");

  return `${label}<code>${escapeHtml(source)}</code>\n`;
}

function renderChildLine(parent: Phile, child: Phile, index: number, labelWidth: number): string {
  const label = padCells(childLabel(index), labelWidth);
  const prefix = `${label}  `;
  const tail = ` ${formatDate(child.data.date)}`;
  const title = stripCtfSuffix(child.data.title, parent.data.ctfTitle ?? stripWriteupsSuffix(parent.data.title));
  const titleWidth = Math.max(1, indexInnerWidth - cellWidth(prefix) - cellWidth(tail) - 6);
  const displayTitle = truncateCells(title, titleWidth);
  const visibleLeft = `${prefix}${displayTitle}`;
  const dots = ".".repeat(Math.max(3, indexInnerWidth - cellWidth(visibleLeft) - cellWidth(tail) - 3));

  return `│ ${escapeHtml(prefix)}${link(child.route.href, displayTitle)} ${dots}${textHtml(tail)} │`;
}

function childLabel(index: number): string {
  return `W.${index + 1}`;
}

function frameLine(input: string): string {
  return `│ ${padCells(input, indexContentWidth)} │`;
}

function stripWriteupsSuffix(input: string): string {
  return input.replace(/\s+Writeups$/i, "");
}

function stripCtfSuffix(input: string, ctfTitle: string): string {
  return input.replace(new RegExp(`\\s+[—-]\\s+${escapeRegExp(ctfTitle)}$`, "i"), "");
}

function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function formatDate(input: Date): string {
  return input.toISOString().slice(0, 10);
}
