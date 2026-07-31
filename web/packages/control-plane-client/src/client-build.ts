import packageManifest from "../../../package.json";

/** Versioned browser/Home compatibility contract (`ITGOV-4`, ADR 0095). */
export const CLIENT_PROTOCOL_VERSION = 1;

export interface ClientBuildDeclaration {
    readonly version: string;
    readonly protocol: number;
    readonly channel: "stable" | "beta" | "dev";
    readonly platform: "desktop" | "web";
}

/** Compatibility evidence reported on every control-plane request. It is never
 * represented as device or binary attestation. */
export function reportedClientBuild(): ClientBuildDeclaration {
    const desktop = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
    return {
        version: packageManifest.version,
        protocol: CLIENT_PROTOCOL_VERSION,
        channel: import.meta.env.DEV ? "dev" : "stable",
        platform: desktop ? "desktop" : "web",
    };
}
