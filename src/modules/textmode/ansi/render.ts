import { externalLink, link, textHtml } from "../core/html";
import { cellWidth } from "../core/layout";
import { normalizeText } from "../core/text";

type AnsiToken = {
  text: string;
  role?: string;
};

type RenderChunk = {
  text: string;
  role?: string;
};

type RenderAnsiOptions = {
  wordWrap?: boolean;
};

type WordGroup = {
  chunks: RenderChunk[];
  width: number;
  whitespace: boolean;
};

const ansiRoles = new Map<string, string>([
  ["k", "black"],
  ["black", "black"],
  ["r", "red"],
  ["red", "red"],
  ["g", "green"],
  ["green", "green"],
  ["y", "yellow"],
  ["yellow", "yellow"],
  ["b", "blue"],
  ["blue", "blue"],
  ["m", "magenta"],
  ["magenta", "magenta"],
  ["c", "cyan"],
  ["cyan", "cyan"],
  ["w", "white"],
  ["white", "white"],
  ["K", "bright-black"],
  ["br-black", "bright-black"],
  ["bright-black", "bright-black"],
  ["R", "bright-red"],
  ["br-red", "bright-red"],
  ["bright-red", "bright-red"],
  ["G", "bright-green"],
  ["br-green", "bright-green"],
  ["bright-green", "bright-green"],
  ["Y", "bright-yellow"],
  ["br-yellow", "bright-yellow"],
  ["bright-yellow", "bright-yellow"],
  ["B", "bright-blue"],
  ["br-blue", "bright-blue"],
  ["bright-blue", "bright-blue"],
  ["M", "bright-magenta"],
  ["br-magenta", "bright-magenta"],
  ["bright-magenta", "bright-magenta"],
  ["C", "bright-cyan"],
  ["br-cyan", "bright-cyan"],
  ["bright-cyan", "bright-cyan"],
  ["W", "bright-white"],
  ["br-white", "bright-white"],
  ["bright-white", "bright-white"]
]);

const inkBlockPattern = /^\s*--\[ ink \]--\s*$/;
const inkMaskPrefixPattern = /^~(.*)$/;
const inkTextPrefixPattern = /^\|(.*)$/;

export function renderAnsiText(input: string, width: number, options: RenderAnsiOptions = {}): string {
  return renderBlocks(normalizeText(input).trim(), width, options).join("\n");
}

function renderBlocks(input: string, width: number, options: RenderAnsiOptions): string[] {
  const lines = input.split("\n");
  const rendered: string[] = [];
  let cursor = 0;

  while (cursor < lines.length) {
    const match = lines[cursor].match(inkBlockPattern);

    if (!match) {
      const textLines: string[] = [];

      while (cursor < lines.length && !lines[cursor].match(inkBlockPattern)) {
        textLines.push(lines[cursor]);
        cursor += 1;
      }

      rendered.push(...renderPlainAnsiLines(textLines.join("\n"), width, options));
      continue;
    }

    const blockLines: string[] = [];
    cursor += 1;

    while (cursor < lines.length && lines[cursor].trim().length > 0) {
      blockLines.push(lines[cursor]);
      cursor += 1;
    }

    rendered.push(...renderInkBlock(blockLines, width));

    if (cursor < lines.length && lines[cursor].trim().length === 0) {
      rendered.push("");
      cursor += 1;
    }
  }

  return rendered;
}

function renderPlainAnsiLines(input: string, width: number, options: RenderAnsiOptions): string[] {
  if (options.wordWrap) {
    return renderWordWrappedAnsiLines(input, width);
  }

  const output: string[] = [];
  let lineChunks: RenderChunk[] = [];
  let lineWidth = 0;

  for (const token of parseInlineAnsi(input)) {
    for (const char of token.text) {
      if (char === "\n") {
        flushLine();
        continue;
      }

      const charWidth = cellWidth(char);

      if (lineWidth + charWidth > width && lineWidth > 0) {
        flushLine();
      }

      appendChunk(lineChunks, { text: char, role: token.role });
      lineWidth += charWidth;
    }
  }

  flushLine();
  return output;

  function flushLine(): void {
    output.push(renderChunks(lineChunks));
    lineChunks = [];
    lineWidth = 0;
  }
}

function renderWordWrappedAnsiLines(input: string, width: number): string[] {
  const output: string[] = [];
  let lineTokens: AnsiToken[] = [];

  for (const token of parseInlineAnsi(input)) {
    const parts = token.text.split("\n");

    for (const [index, part] of parts.entries()) {
      if (index > 0) {
        flushLogicalLine();
      }

      if (part.length > 0) {
        lineTokens.push({ text: part, role: token.role });
      }
    }
  }

  flushLogicalLine();
  return output;

  function flushLogicalLine(): void {
    output.push(...renderWordWrappedLine(lineTokens, width));
    lineTokens = [];
  }
}

function renderWordWrappedLine(tokens: AnsiToken[], width: number): string[] {
  const groups = wordGroups(tokens);
  const output: string[] = [];
  let lineChunks: RenderChunk[] = [];
  let lineWidth = 0;
  let pendingSpace: WordGroup | undefined;

  for (const group of groups) {
    if (group.whitespace) {
      if (lineWidth === 0) {
        appendGroup(group);
      } else {
        pendingSpace = group;
      }
      continue;
    }

    if (group.width > width) {
      appendPendingSpace();
      appendHardWrappedGroup(group);
      pendingSpace = undefined;
      continue;
    }

    const pendingWidth = pendingSpace?.width ?? 0;

    if (lineWidth > 0 && lineWidth + pendingWidth + group.width > width) {
      flushLine();
      pendingSpace = undefined;
    } else {
      appendPendingSpace();
    }

    appendGroup(group);
  }

  flushLine();
  return output.length > 0 ? output : [""];

  function appendPendingSpace(): void {
    if (!pendingSpace) {
      return;
    }

    appendGroup(pendingSpace);
    pendingSpace = undefined;
  }

  function appendGroup(group: WordGroup): void {
    for (const chunk of group.chunks) {
      appendChunk(lineChunks, chunk);
    }

    lineWidth += group.width;
  }

  function appendHardWrappedGroup(group: WordGroup): void {
    for (const chunk of group.chunks) {
      for (const char of chunk.text) {
        const charWidth = cellWidth(char);

        if (lineWidth + charWidth > width && lineWidth > 0) {
          flushLine();
        }

        appendChunk(lineChunks, { text: char, role: chunk.role });
        lineWidth += charWidth;
      }
    }
  }

  function flushLine(): void {
    output.push(renderChunks(lineChunks));
    lineChunks = [];
    lineWidth = 0;
  }
}

function wordGroups(tokens: AnsiToken[]): WordGroup[] {
  const groups: WordGroup[] = [];

  for (const token of tokens) {
    for (const part of token.text.match(/\s+|\S+/g) ?? []) {
      const whitespace = /^\s+$/u.test(part);
      const previous = groups.at(-1);
      const chunk = { text: part, role: token.role };

      if (previous && previous.whitespace === whitespace) {
        previous.chunks.push(chunk);
        previous.width += cellWidth(part);
      } else {
        groups.push({
          chunks: [chunk],
          width: cellWidth(part),
          whitespace
        });
      }
    }
  }

  return groups;
}

function renderInkBlock(lines: string[], width: number): string[] {
  const output: string[] = [];
  let cursor = 0;

  while (cursor < lines.length) {
    const textMatch = lines[cursor].match(inkTextPrefixPattern);
    const maskMatch = lines[cursor + 1]?.match(inkMaskPrefixPattern);

    if (textMatch && maskMatch) {
      output.push(...renderInkTextLine(textMatch[1] ?? "", maskMatch[1] ?? "", width));
      cursor += 2;
      continue;
    }

    if (lines[cursor].match(inkMaskPrefixPattern)) {
      cursor += 1;
      continue;
    }

    output.push(...renderPlainAnsiLines(lines[cursor], width, {}));
    cursor += 1;
  }

  return output;
}

function renderInkTextLine(text: string, mask: string, width: number): string[] {
  const chunks: RenderChunk[] = [];
  let index = 0;

  for (const char of text) {
    const role = roleForMask(mask[index]);
    appendChunk(chunks, { text: char, role });
    index += 1;
  }

  return renderWrappedChunks(chunks, width);
}

function parseInlineAnsi(input: string): AnsiToken[] {
  const tokens: AnsiToken[] = [];
  let cursor = 0;
  let plain = "";

  while (cursor < input.length) {
    if (input[cursor] === "\\" && cursor + 1 < input.length) {
      plain += input[cursor + 1];
      cursor += 2;
      continue;
    }

    if (input.startsWith("#[", cursor)) {
      const parsed = parseMarker(input, cursor);

      if (parsed) {
        flushPlain();
        tokens.push({ text: parsed.text, role: parsed.role });
        cursor = parsed.end;
        continue;
      }
    }

    plain += input[cursor];
    cursor += 1;
  }

  flushPlain();
  return tokens;

  function flushPlain(): void {
    if (plain.length > 0) {
      tokens.push({ text: plain });
      plain = "";
    }
  }
}

function parseMarker(input: string, start: number): { role: string; text: string; end: number } | undefined {
  const pipe = findUnescaped(input, "|", start + 2);

  if (pipe === -1) {
    return undefined;
  }

  const close = findUnescaped(input, "]", pipe + 1);

  if (close === -1) {
    return undefined;
  }

  const alias = input.slice(start + 2, pipe).trim();
  const role = ansiRoles.get(alias);

  if (!role) {
    throw new Error(`Unknown ANSI role "${alias}".`);
  }

  return {
    role,
    text: unescapeAnsiText(input.slice(pipe + 1, close)),
    end: close + 1
  };
}

function findUnescaped(input: string, needle: string, start: number): number {
  for (let index = start; index < input.length; index += 1) {
    if (input[index] === "\\" && index + 1 < input.length) {
      index += 1;
      continue;
    }

    if (input[index] === needle) {
      return index;
    }
  }

  return -1;
}

function unescapeAnsiText(input: string): string {
  return input.replace(/\\([#[\]|\\])/g, "$1");
}

function roleForMask(char: string | undefined): string | undefined {
  if (!char || char === "." || char === " ") {
    return undefined;
  }

  const role = ansiRoles.get(char);

  if (!role) {
    throw new Error(`Unknown ink mask "${char}".`);
  }

  return role;
}

function appendChunk(chunks: RenderChunk[], chunk: RenderChunk): void {
  const previous = chunks[chunks.length - 1];

  if (previous && previous.role === chunk.role) {
    previous.text += chunk.text;
    return;
  }

  chunks.push(chunk);
}

function renderChunks(chunks: RenderChunk[]): string {
  return chunks
    .map((chunk) =>
      chunk.role
        ? `<span class="ansi ansi-${chunk.role}">${linkedTextHtml(chunk.text)}</span>`
        : linkedTextHtml(chunk.text)
    )
    .join("");
}

function linkedTextHtml(input: string): string {
  const autoLinkPattern = /https?:\/\/[^\s<>"')]+|mailto:[^\s<>"')]+|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
  let html = "";
  let cursor = 0;

  for (const match of input.matchAll(autoLinkPattern)) {
    const candidate = match[0] ?? "";
    const index = match.index ?? 0;
    const { href, label, trailing } = splitTrailingPunctuation(candidate);

    html += textHtml(input.slice(cursor, index));
    html += autoLink(href, label);
    html += textHtml(trailing);
    cursor = index + candidate.length;
  }

  return `${html}${textHtml(input.slice(cursor))}`;
}

function autoLink(href: string, label: string): string {
  if (href.toLowerCase().startsWith("mailto:")) {
    return link(href, label.replace(/^mailto:/i, ""));
  }

  if (isEmailAddress(href)) {
    return link(`mailto:${href}`, label);
  }

  return externalLink(href, label);
}

function isEmailAddress(input: string): boolean {
  return /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i.test(input);
}

function splitTrailingPunctuation(url: string): { href: string; label: string; trailing: string } {
  const trailing = url.match(/[.,;:!?]+$/)?.[0] ?? "";
  const href = trailing.length > 0 ? url.slice(0, -trailing.length) : url;

  return {
    href,
    label: href,
    trailing
  };
}

function renderWrappedChunks(chunks: RenderChunk[], width: number): string[] {
  const output: string[] = [];
  let lineChunks: RenderChunk[] = [];
  let lineWidth = 0;

  for (const chunk of chunks) {
    for (const char of chunk.text) {
      const charWidth = cellWidth(char);

      if (lineWidth + charWidth > width && lineWidth > 0) {
        flushLine();
      }

      appendChunk(lineChunks, { text: char, role: chunk.role });
      lineWidth += charWidth;
    }
  }

  flushLine();
  return output;

  function flushLine(): void {
    output.push(renderChunks(lineChunks));
    lineChunks = [];
    lineWidth = 0;
  }
}
