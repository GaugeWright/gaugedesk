import packageManifest from "../../../package.json";

/** Versioned browser/Home compatibility contract (`ITGOV-4`, ADR 0095). */
export const CLIENT_PROTOCOL_VERSION = 1;

/** The version a release stamps into the frontend bundle, derived from the git
 * tag by `release.yml`'s resolve step. The in-repo manifest version is a dev
 * default, not a release fact: a released build's bundle name comes from the
 * tag, so a build that reported the manifest reported a version no released
 * artifact ever had. v0.4.6 through v0.4.8 all shipped saying 0.4.5. Unset in
 * dev, local, and hosted-web builds, which have no tag to speak for and fall
 * back to the manifest. */
const STAMPED_RELEASE_VERSION = import.meta.env.VITE_GAUGEDESK_RELEASE_VERSION as
    | string
    | undefined;

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
        version: STAMPED_RELEASE_VERSION || packageManifest.version,
        protocol: CLIENT_PROTOCOL_VERSION,
        channel: import.meta.env.DEV ? "dev" : "stable",
        platform: desktop ? "desktop" : "web",
    };
}
