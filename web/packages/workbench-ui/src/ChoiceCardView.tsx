import { createSignal, For, Show, type JSX } from "solid-js";
import type { ChoiceCard, ChoiceSelection } from "@gaugewright/control-plane-client";

/** One durable question card, shared by work chats and public Panels. */
export function ChoiceCardView(props: {
    card: ChoiceCard;
    onAnswer: (selections: ChoiceSelection[]) => Promise<void>;
}): JSX.Element {
    const [picked, setPicked] = createSignal<Record<string, string[]>>({});
    const [others, setOthers] = createSignal<Record<string, string>>({});
    const [pending, setPending] = createSignal(false);
    const [error, setError] = createSignal("");
    const complete = () => props.card.questions.every((question) =>
        Boolean(others()[question.id]?.trim()) || (picked()[question.id]?.length ?? 0) > 0);
    const choose = (questionId: string, optionId: string, multiple: boolean) => {
        setOthers((current) => ({ ...current, [questionId]: "" }));
        setPicked((current) => {
            const previous = current[questionId] ?? [];
            const next = multiple
                ? previous.includes(optionId)
                    ? previous.filter((id) => id !== optionId)
                    : [...previous, optionId]
                : [optionId];
            return { ...current, [questionId]: next };
        });
    };
    const submit = async () => {
        if (pending() || !complete()) return;
        setPending(true);
        setError("");
        const selections = props.card.questions.map((question) => ({
            question_id: question.id,
            option_ids: others()[question.id]?.trim() ? [] : picked()[question.id] ?? [],
            other: others()[question.id]?.trim() || null,
        }));
        try {
            await props.onAnswer(selections);
        } catch (cause) {
            setError(cause instanceof Error ? cause.message : "Could not submit the answer.");
        } finally {
            setPending(false);
        }
    };
    const retryContinuation = async () => {
        if (!props.card.answer || pending()) return;
        setPending(true);
        setError("");
        try {
            await props.onAnswer(props.card.answer.selections);
        } catch (cause) {
            setError(cause instanceof Error ? cause.message : "The agent could not continue yet.");
        } finally {
            setPending(false);
        }
    };
    return (
        <section class="choice-card" data-choice-card={props.card.id} aria-label="Agent questions">
            <div class="choice-card-heading">{props.card.blocking ? "Your answer is needed" : "A question for you"}</div>
            <For each={props.card.questions}>
                {(question) => {
                    const answered = () => props.card.answer?.selections.find((item) => item.question_id === question.id);
                    return (
                        <fieldset class="choice-question" disabled={Boolean(props.card.answer) || pending()}>
                            <legend>{question.prompt}</legend>
                            <Show when={!props.card.answer} fallback={
                                <div class="choice-answer">
                                    {answered()?.other
                                        ? `Other: ${answered()?.other}`
                                        : answered()?.option_ids.map((id) => question.options.find((option) => option.id === id)?.label ?? id).join(", ")}
                                </div>
                            }>
                                <For each={question.options}>
                                    {(option) => (
                                        <label class="choice-option" classList={{ recommended: question.recommended_option_id === option.id }}>
                                            <input
                                                type={question.multiple ? "checkbox" : "radio"}
                                                name={`${props.card.id}-${question.id}`}
                                                checked={(picked()[question.id] ?? []).includes(option.id) && !others()[question.id]?.trim()}
                                                onChange={() => choose(question.id, option.id, question.multiple)}
                                            />
                                            <span><strong>{option.label}</strong><small>{option.description}</small></span>
                                            <Show when={question.recommended_option_id === option.id}><em>Recommended</em></Show>
                                        </label>
                                    )}
                                </For>
                                <label class="choice-other">
                                    <span>{question.options.length ? "Other" : "Your answer"}</span>
                                    <textarea
                                        value={others()[question.id] ?? ""}
                                        rows={2}
                                        maxLength={2000}
                                        placeholder="Write your answer"
                                        onInput={(event) => {
                                            const value = event.currentTarget.value;
                                            setOthers((current) => ({ ...current, [question.id]: value }));
                                            if (value.trim()) setPicked((current) => ({ ...current, [question.id]: [] }));
                                        }}
                                    />
                                </label>
                            </Show>
                        </fieldset>
                    );
                }}
            </For>
            <Show when={props.card.answer} fallback={
                <button type="button" disabled={!complete() || pending()} onClick={() => void submit()}>
                    {pending() ? "Submitting…" : "Submit answer"}
                </button>
            }>
                <div class="choice-attribution">Answered by {props.card.answer?.answered_by}</div>
                <Show when={!props.card.continuation || props.card.continuation.status === "pending"}>
                    <div class="choice-attribution">Agent continuation pending</div>
                    <button type="button" disabled={pending()} onClick={() => void retryContinuation()}>
                        {pending() ? "Continuing…" : "Continue agent"}
                    </button>
                </Show>
                <Show when={props.card.continuation?.status === "refused"}>
                    <p class="choice-error" role="alert">{props.card.continuation?.error ?? "The agent could not continue."}</p>
                </Show>
            </Show>
            <Show when={error()}><p class="choice-error" role="alert">{error()}</p></Show>
        </section>
    );
}
