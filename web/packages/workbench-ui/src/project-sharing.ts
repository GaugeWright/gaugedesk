import type { Participant, ProjectShareCandidate } from "@gaugewright/control-plane-client";

/** Directory identities still eligible for this Project Home. Revoked access
 * does not suppress a fresh invitation; current access does. */
export function availableProjectShareCandidates(
    candidates: readonly ProjectShareCandidate[],
    participants: readonly Participant[],
): ProjectShareCandidate[] {
    const current = new Set(participants
        .filter((participant) => !participant.revoked)
        .map((participant) => participant.authority));
    return candidates.filter((candidate) => !current.has(candidate.authority));
}
