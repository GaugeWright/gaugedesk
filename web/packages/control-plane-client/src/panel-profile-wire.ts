import type { PanelPublicProfile } from "./control-plane-domain";

/** The provider posture a Panel-agent profile carried before gaugedesk-src
 *  DR-0272. A Home running an older GaugeDesk still sends and requires it, and
 *  the web client is served to Homes of every version at once. */
export interface LegacyPanelProvider {
    readonly provider: string;
    readonly model: string;
    readonly base_url: string;
    readonly credential_class: string;
    readonly max_input_tokens?: number;
    readonly max_output_tokens?: number;
}

/** The posture every Panel agent was created with before DR-0272. Nobody chose
 *  it, so a profile still carrying it exactly is unpinned — the same rule the
 *  Home applies to a version frozen before that decision. */
const LEGACY_DEFAULT = {
    provider: "openai",
    model: "gpt-5-mini",
    base_url: "https://api.openai.com",
    credential_class: "openai-api-key",
} as const;

type WireProfile = Omit<PanelPublicProfile, "model" | "legacyProvider"> & {
    readonly model?: PanelPublicProfile["model"];
    readonly provider?: LegacyPanelProvider;
};

/** A profile as the Home sent it, in the shape the client works with.
 *
 *  An older Home's `provider` becomes a model pin (or none, for the untouched
 *  default), and is kept so the profile can be written back in the shape that
 *  Home accepts. Reading `profile.model` on such a profile threw, which was
 *  every Deploy click on 2026-10-01 against a Home that predates DR-0272. */
export function panelProfileFromWire(raw: unknown): PanelPublicProfile {
    const wire = raw as WireProfile;
    if (wire.model || !wire.provider) {
        const { provider: _ignored, ...current } = wire;
        return { ...current, model: wire.model ?? {} } as PanelPublicProfile;
    }
    const { provider, ...rest } = wire;
    const untouched = provider.provider === LEGACY_DEFAULT.provider
        && provider.model === LEGACY_DEFAULT.model
        && provider.base_url === LEGACY_DEFAULT.base_url
        && provider.credential_class === LEGACY_DEFAULT.credential_class;
    return {
        ...rest,
        model: {
            ...(untouched ? {} : { pinned: provider.model }),
            ...(provider.max_input_tokens !== undefined ? { max_input_tokens: provider.max_input_tokens } : {}),
            ...(provider.max_output_tokens !== undefined ? { max_output_tokens: provider.max_output_tokens } : {}),
        },
        legacyProvider: provider,
    } as PanelPublicProfile;
}

/** A profile in the shape its Home accepts: `model` for a current Home, the
 *  older `provider` posture for a Home that sent one. */
export function panelProfileToWire(profile: PanelPublicProfile): unknown {
    const { legacyProvider, model, ...rest } = profile;
    if (!legacyProvider) return { ...rest, model };
    const provider: LegacyPanelProvider = {
        provider: legacyProvider.provider,
        model: model.pinned ?? legacyProvider.model,
        base_url: legacyProvider.base_url,
        credential_class: legacyProvider.credential_class,
        ...(model.max_input_tokens !== undefined ? { max_input_tokens: model.max_input_tokens } : {}),
        ...(model.max_output_tokens !== undefined ? { max_output_tokens: model.max_output_tokens } : {}),
    };
    return { ...rest, provider };
}
