import { describe, expect, it } from "vitest";
import { DEFAULT_COMPOSER_MODE, loadDefaultMode, saveDefaultMode } from "./composer-mode";

function store(initial?: string) {
    const cell = { value: initial };
    return {
        getItem: () => cell.value ?? null,
        setItem: (_key: string, value: string) => {
            cell.value = value;
        },
        read: () => cell.value,
    };
}

describe("the default composer mode", () => {
    it("round-trips a stored choice", () => {
        const s = store();
        saveDefaultMode(s, "stash");
        expect(loadDefaultMode(s)).toBe("stash");
    });

    it("falls back rather than throwing on anything unrecognised", () => {
        // An older writer, a newer one, or a hand-edited value: a bad preference
        // should cost a default, never a composer.
        for (const raw of ["", "review", "fork", "{}", "STASH"]) {
            expect(loadDefaultMode(store(raw))).toBe(DEFAULT_COMPOSER_MODE);
        }
        expect(loadDefaultMode(null)).toBe(DEFAULT_COMPOSER_MODE);
    });

    it("survives storage that refuses to answer", () => {
        const hostile = {
            getItem: () => {
                throw new Error("storage disabled");
            },
            setItem: () => {
                throw new Error("storage disabled");
            },
        };
        expect(loadDefaultMode(hostile)).toBe(DEFAULT_COMPOSER_MODE);
        expect(() => saveDefaultMode(hostile, "queue")).not.toThrow();
    });

    it("defaults to steer, the one mode reachable everywhere", () => {
        expect(DEFAULT_COMPOSER_MODE).toBe("steer");
        expect(loadDefaultMode(store())).toBe("steer");
    });
});
