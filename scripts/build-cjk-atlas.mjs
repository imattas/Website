import { execFileSync } from "node:child_process";
import { accessSync, constants, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const pyftsubset = findCommand("pyftsubset");
const python = pythonFromShebang(pyftsubset);
const script = path.join(root, "scripts/build-cjk-atlas.py");

execFileSync(python, [script], { cwd: root, stdio: "inherit" });

function findCommand(command) {
  for (const directory of (process.env.PATH ?? "").split(path.delimiter)) {
    const candidate = path.join(directory, command);

    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Keep searching PATH.
    }
  }

  throw new Error(`Missing ${command}; install fonttools first.`);
}

function pythonFromShebang(commandPath) {
  const firstLine = readFileSync(commandPath, "utf8").split("\n")[0] ?? "";
  const match = firstLine.match(/^#!(.+)$/);

  if (!match) {
    throw new Error(`Cannot read Python interpreter from ${commandPath}`);
  }

  return match[1].trim();
}
