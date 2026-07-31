import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

async function filesBelow(root, relative = "") {
    const entries = await readdir(resolve(root, relative), { withFileTypes: true })
        .catch((error) => {
            if (error?.code === "ENOENT") return [];
            throw error;
        });
    const files = [];
    for (const entry of entries.sort((left, right) =>
        left.name.localeCompare(right.name))) {
        const child = relative ? `${relative}/${entry.name}` : entry.name;
        if (entry.isDirectory()) files.push(...await filesBelow(root, child));
        else if (entry.isFile()) files.push(child);
    }
    return files;
}

async function sqliteDump(path) {
    return (await execFileAsync("sqlite3", [path, ".dump"], {
        maxBuffer: 16 * 1024 * 1024,
    })).stdout;
}

function withoutOperationalRows(dump) {
    return dump
        .split("\n")
        .filter((line) =>
            !line.startsWith("INSERT INTO events VALUES('audit',")
            && !line.startsWith("INSERT INTO events VALUES('audit_checkpoint',")
            && !line.startsWith("INSERT INTO command_receipts VALUES(")
            && !line.startsWith("INSERT INTO commands VALUES("))
        .join("\n");
}

export async function stateTreeDigest(root) {
    const hash = createHash("sha256");
    for (const path of await filesBelow(root)) {
        if (path.endsWith("-wal") || path.endsWith("-shm")) continue;
        const absolute = resolve(root, path);
        const contents = path.endsWith(".db")
            ? withoutOperationalRows(await sqliteDump(absolute))
            : await readFile(absolute);
        hash.update(path);
        hash.update("\0");
        hash.update(contents);
        hash.update("\0");
    }
    return hash.digest("hex");
}

export async function assertStateUnchanged(root, before, surface) {
    const after = await stateTreeDigest(root);
    if (after !== before) {
        throw new Error(
            `${surface} changed authoritative state (${before} -> ${after})`,
        );
    }
}

export async function assertStateTreeExcludes(root, forbidden, surface) {
    for (const path of await filesBelow(root)) {
        const contents = await readFile(resolve(root, path));
        for (const value of forbidden) {
            if (contents.includes(Buffer.from(value))) {
                throw new Error(
                    `${surface} persisted forbidden plaintext in ${path}`,
                );
            }
        }
    }
}
