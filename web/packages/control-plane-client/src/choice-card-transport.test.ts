// @vitest-environment node
// WS71 production helpers/router/socket; controls change synthetic standing only.
import { spawn, type ChildProcess } from "node:child_process";
import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { afterAll, beforeAll, expect, it } from "vitest";
import { RemoteControlPlane } from "./remote-control-plane";
import type { EngagementId } from "./control-plane-domain";
type Ready = { protocol: string; base: string; chat: EngagementId; owner: string; participant: string;
    stranger: string; admissions: [string, string][]; cards: string[] };
let child: ChildProcess | undefined, ready: Ready, raw = "";
let closed: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
let pending: ((value: { op: string; provider_calls: number }) => void) | undefined;
async function bounded<T>(promise: Promise<T>, ms: number, why: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try { return await Promise.race([promise, new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${why}\n${raw}`)), ms);
    })]); } finally { if (timer) clearTimeout(timer); }
}
function client(actor: string) { return new RemoteControlPlane(ready.base, { bearer: actor,
    homeAdmission: ready.admissions.find(([person]) => person === actor)![1] }); }
async function control(op: string) {
    const result = new Promise<{ op: string; provider_calls: number }>((resolve) => { pending = resolve; });
    child!.stdin!.write(`${JSON.stringify({ op })}\n`);
    const observed = await bounded(result, 10_000, "owned fixture control");
    expect(observed.op).toBe(op); return observed;
}
async function stop() {
    if (!child) return; child.stdin?.end();
    try { expect(await bounded(closed, 5000, "fixture EOF retirement")).toEqual({ code: 0, signal: null }); }
    catch (error) {
        child.kill("SIGTERM");
        try { await bounded(closed, 2000, "fixture TERM retirement"); }
        catch { child.kill("SIGKILL"); await bounded(closed, 2000, "fixture KILL retirement"); }
        throw error;
    } finally { child = undefined; }
}
beforeAll(async () => {
    const executable = process.env.GAUGEDESK_PANEL_AUTHORING_FIXTURE;
    if (!executable) throw new Error("choice routes require the declared app-library fixture producer");
    await access(executable, constants.X_OK);
    child = spawn(executable, ["--ignored", "--exact", "raw_model_context_runtime_tests::choice_routes::serve", "--nocapture"], { stdio: ["pipe", "pipe", "pipe"] });
    closed = new Promise((resolve, reject) => { child!.once("error", reject); child!.once("close", (code, signal) => resolve({ code, signal })); });
    const started = new Promise<Ready>((resolve, reject) => {
        let buffer = "";
        child!.stdout!.on("data", (bytes: Buffer) => {
            const text = bytes.toString(); raw += text; buffer += text;
            const lines = buffer.split("\n"); buffer = lines.pop()!;
            for (const line of lines) {
                if (line.startsWith("WS71_CHOICE_READY ")) resolve(JSON.parse(line.slice("WS71_CHOICE_READY ".length)) as Ready);
                if (line.startsWith("WS71_CHOICE_CONTROL ")) { pending?.(JSON.parse(line.slice("WS71_CHOICE_CONTROL ".length))); pending = undefined; }
            }
        });
        child!.stderr!.on("data", (bytes: Buffer) => { raw += bytes.toString(); });
        closed.then((result) => reject(new Error(`fixture closed before readiness ${JSON.stringify(result)}\n${raw}`)), reject);
    });
    try {
        ready = await bounded(started, 120_000, "native choice fixture readiness");
        expect(ready.protocol).toBe("gaugedesk.choice-route-fixture.v1");
        expect(new URL(ready.base).hostname).toBe("127.0.0.1");
    } catch (error) { try { await stop(); } catch (cleanup) { throw new AggregateError([error, cleanup], "setup and cleanup failed"); } throw error; }
}, 125_000);
afterAll(stop, 15_000);
it("choice-route-production-client admits participants and preserves attribution and retry through reload and durable reopen", async () => {
    const owner = client(ready.owner), participant = client(ready.participant), stranger = client(ready.stranger);
    const cards = await owner.getChoiceCards(ready.chat); expect(cards).toHaveLength(2);
    const first = cards.find((card) => card.id === ready.cards[0])!;
    expect(first.recipient).toBe(ready.owner);
    const selections = [{ question_id: first.questions[0].id, option_ids: [first.questions[0].options[0].id], other: null }];
    const before = JSON.stringify(cards);
    await expect(stranger.getChoiceCards(ready.chat)).rejects.toMatchObject({ status: 403 });
    await expect(stranger.answerChoiceCard(ready.chat, first.id, selections)).rejects.toMatchObject({ status: 403 });
    await expect(new RemoteControlPlane(ready.base, { bearer: ready.owner }).getChoiceCards(ready.chat)).rejects.toMatchObject({ status: 401 });
    await expect(new RemoteControlPlane(ready.base, { homeAdmission: ready.admissions[0][1] }).getChoiceCards(ready.chat)).rejects.toMatchObject({ status: 401 });
    await expect(new RemoteControlPlane(ready.base, { bearer: ready.participant,
        homeAdmission: ready.admissions.find(([person]) => person === ready.owner)![1] }).getChoiceCards(ready.chat)).rejects.toMatchObject({ status: 403 });
    expect(await control("observe")).toMatchObject({ provider_calls: 0 });
    await control("revoke-participant");
    await expect(participant.getChoiceCards(ready.chat)).rejects.toMatchObject({ status: 403 });
    await expect(participant.answerChoiceCard(ready.chat, first.id, selections)).rejects.toMatchObject({ status: 403 });
    expect(JSON.stringify(await owner.getChoiceCards(ready.chat))).toBe(before);
    await control("restore-participant");
    await expect(participant.answerChoiceCard(ready.chat, first.id, [])).rejects.toMatchObject({ status: 400 });
    expect(await control("observe")).toMatchObject({ provider_calls: 0 });
    await participant.answerChoiceCard(ready.chat, first.id, selections);
    const answered = (await client(ready.owner).getChoiceCards(ready.chat)).find((card) => card.id === first.id)!;
    expect(answered.recipient).toBe(ready.owner); expect(answered.answer?.answered_by).toBe(ready.participant);
    expect(answered.answer?.selections).toEqual(selections.map((value) => ({ ...value, other: null })));
    expect(answered.continuation?.status).toBe("completed");
    expect(await control("observe")).toMatchObject({ provider_calls: 1 });
    await participant.answerChoiceCard(ready.chat, first.id, selections);
    await expect(owner.answerChoiceCard(ready.chat, first.id, selections)).rejects.toMatchObject({ reason: "choice card was already answered by another response" });
    expect(await control("observe")).toMatchObject({ provider_calls: 1 });
    const retained = await owner.getChoiceCards(ready.chat);
    await control("reopen"); await owner.admitHome(); await participant.admitHome();
    expect(await owner.getChoiceCards(ready.chat)).toEqual(retained);
    await participant.answerChoiceCard(ready.chat, first.id, selections);
    expect(await control("observe")).toMatchObject({ provider_calls: 1 });
    const second=(await owner.getChoiceCards(ready.chat)).find((card)=>card.id===ready.cards[1])!;
    expect(second.questions).toHaveLength(2);
    expect(second.questions[0].multiple).toBe(true);
    const multiple=[{ question_id:second.questions[0].id,option_ids:second.questions[0].options.slice(0,2).map((option)=>option.id),other:null },
        { question_id:second.questions[1].id,option_ids:[],other:"Synthetic Other" }];
    await expect(owner.answerChoiceCard(ready.chat,second.id,multiple.slice(0,1))).rejects.toMatchObject({status:400});
    await owner.answerChoiceCard(ready.chat,second.id,multiple);
    const ownAnswer=(await owner.getChoiceCards(ready.chat)).find((card)=>card.id===second.id)!;
    expect(ownAnswer.answer?.answered_by).toBe(ready.owner);
    expect(ownAnswer.answer?.selections).toEqual(multiple);
    expect(await control("observe")).toMatchObject({provider_calls:2});
    const retired=client(ready.participant);
    await retired.admitHome(); await retired.revokeHomeAdmission();
    await expect(retired.getChoiceCards(ready.chat)).rejects.toMatchObject({status:401});

}, 30_000);
