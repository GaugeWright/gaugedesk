/** The components the GaugeApps prototype's information design is built from.
 *
 *  `Fact` in AdministrationGaugeApp already covers a labelled value inside a
 *  record. These are the rest, and the GaugeApps were implemented without them,
 *  which is most of why a built page reads as a list where the design reads as
 *  a statement followed by its evidence.
 */
import { Show, type JSX } from "solid-js";

/** The three components the prototype's information design is built from, which
 *  the GaugeApps were implemented without. `Fact` above already covers what the
 *  prototype calls a metric on a detail page; these are the rest.
 *
 *  A `Notice` states the model a page is about before the page shows any of it —
 *  what a Project Host is, that Trusted Devices are not one, that a session here
 *  is not a commercial client. The prototype opens nine of its panels this way,
 *  and a page that skips it makes the reader infer the model from the rows.
 */
export function Notice(props: { tone: "neutral" | "warn"; children: JSX.Element }): JSX.Element {
    return <div class="gaugeapp-notice" data-tone={props.tone}>{props.children}</div>;
}

/** A counted fact above a section, tinted when it is the one that needs
 *  attention. Distinct from `Fact`, which labels a value inside a record. */
export function Metric(props: { label: string; value: string; note: string; tone?: "warn" }): JSX.Element {
    return <div class="gaugeapp-metric" data-tone={props.tone ?? "neutral"}>
        <span>{props.label}</span>
        <strong>{props.value}</strong>
        <small>{props.note}</small>
    </div>;
}

/** A section's title, an optional count beside it, and the one action that
 *  belongs to the section rather than to a row in it. */
export function SectionHeading(props: { title: string; meta?: string; action?: string; onAction?: () => void }): JSX.Element {
    return <div class="gaugeapp-section-heading">
        <div><h4>{props.title}</h4><Show when={props.meta}>{(meta) => <span>{meta()}</span>}</Show></div>
        <Show when={props.action && props.onAction}>
            <button type="button" onClick={props.onAction}>{props.action}</button>
        </Show>
    </div>;
}

/** One admitted thing, its posture, and what can be done to it.
 *
 *  The two features the built pages had no way to express: `tone`, so a row that
 *  needs attention says so where it sits rather than in a status column, and a
 *  *secondary* action, so an unreachable host can offer both `diagnose` and
 *  `disconnect` without a menu.
 */
export function Resource(props: {
    kind: string;
    title: string;
    detail: string;
    tone: "ready" | "warn" | "neutral";
    action?: string;
    onAction?: () => void;
    secondaryAction?: string;
    onSecondaryAction?: () => void;
}): JSX.Element {
    return <div class="gaugeapp-resource" data-tone={props.tone}>
        <span class="gaugeapp-resource-identity">
            <span class="gaugeapp-resource-title">{props.title}</span>
            <span class="gaugeapp-resource-kind">{props.kind}</span>
            <small>{props.detail}</small>
        </span>
        <Show when={props.action || props.secondaryAction}>
            <span class="gaugeapp-resource-actions">
                <Show when={props.action && props.onAction}>
                    <button type="button" onClick={props.onAction}>{props.action}</button>
                </Show>
                <Show when={props.secondaryAction && props.onSecondaryAction}>
                    <button type="button" onClick={props.onSecondaryAction}>{props.secondaryAction}</button>
                </Show>
            </span>
        </Show>
    </div>;
}
