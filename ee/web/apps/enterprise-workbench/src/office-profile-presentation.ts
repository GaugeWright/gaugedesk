/**
 * The office-controlled profile panel on Organization Policy (WS-424).
 *
 * Enrollment binds this organization to the Project Host it names and has no
 * exit, so the panel says which host will hold the work, says that it is
 * permanent, and offers the command only while the server reports it
 * `available`, the administrator holds it, and they have acknowledged both.
 */
export type OfficeProfileStateView =
    | { readonly state: "enrolled"; readonly home_id: string; readonly this_home: string; readonly bound_here: boolean; readonly enrolled_by: string; readonly enrolled_at_ms: number }
    | { readonly state: "available"; readonly this_home: string }
    | { readonly state: "unavailable"; readonly this_home: string | null; readonly reason: string };

export interface OfficeProfilePresentation {
    readonly status: string;
    readonly detail: string;
    readonly host: string | null;
    readonly tone: "neutral" | "warn";
    /** Whether to show the acknowledgement and the enroll action at all. */
    readonly offerEnrollment: boolean;
    /** The exact payload to submit, or null while it cannot be submitted. */
    readonly enrollPayload: { readonly home_id: string } | null;
}

export const OFFICE_PROFILE_COMMAND = "office-profile.enroll";

export function officeProfilePresentation(
    profile: OfficeProfileStateView,
    commands: readonly string[],
    acknowledged: boolean,
): OfficeProfilePresentation {
    if (profile.state === "enrolled") {
        return {
            status: "Enrolled",
            detail: profile.bound_here
                ? "This organization's work stays on this Project Host. Projects cannot move to another Home or be transferred to an account, and there is no way to leave the profile."
                : "This organization is bound to another Project Host. This Home serves no office staff and nothing can leave it.",
            host: profile.home_id,
            tone: profile.bound_here ? "neutral" : "warn",
            offerEnrollment: false,
            enrollPayload: null,
        };
    }
    if (profile.state === "unavailable") {
        return {
            status: "Unavailable",
            detail: profile.reason,
            host: profile.this_home,
            tone: "neutral",
            offerEnrollment: false,
            enrollPayload: null,
        };
    }
    const permitted = commands.includes(OFFICE_PROFILE_COMMAND);
    return {
        status: "Not enrolled",
        detail: permitted
            ? "Enrolling keeps this organization's work on the Project Host below. It is permanent: projects can no longer move to another Home or be transferred to an account."
            : "Only an organization administrator can enroll this organization.",
        host: profile.this_home,
        tone: "neutral",
        offerEnrollment: permitted,
        enrollPayload: permitted && acknowledged ? { home_id: profile.this_home } : null,
    };
}
