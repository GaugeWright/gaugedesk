# Inference

This document is how you operate the inference engine on this box. You never
need a shell on it.

## What you are looking at

Everything on this page except **Requested model** and **Autostart** is a
projection — the box's own report of its state, refreshed when you open the
document. You cannot edit a projection into being true.

`desired` is the exception, and it is a request rather than a fact. The box
reconciles toward it. The view has no editable fields — to change what is
requested, open this document's literal JSON and edit the `desired` block.

Setting a model the box does not have will refuse rather than silently download
it; the model has to appear in the table first.

## Why the controls are sometimes inert

A control renders as *Unavailable in this session* when the Home did not
advertise that command for you. That is the authorization answer itself, not a
loading state — the view has no way to make a command available, and no way to
invent one that the Home does not own.

## What is deliberately not here

**No request or response content, ever.** The activity table carries engine
lifecycle events only: starts, stops, model loads, updates, hardware faults. An
inference engine's own request log routinely contains prompt and completion
text, so it is not projected here at all — not truncated, not redacted, not
behind a capability. If you need it, read it on the box under your own
authority, where its handling is your decision rather than this document's.

**No key material.** The engine requires a key on every request, on both the
relay path and the direct WireGuard path — reaching the box is never enough to
use it. No key value appears in this document or any other; a key is shown once,
when it is issued, and never again.

**No listening address you could connect to from here.** The address shown is
the engine's own loopback bind, so that you can confirm it is loopback. The
direct WireGuard interface, when it is on, is reported in the posture document
where it belongs alongside the rest of the box's exposure.

## When the engine will not start

Check **Last error** first, then the activity table. The common causes are a
model that no longer fits VRAM after a driver change, a partial download left in
`incomplete`, and a pinned engine version that does not match the installed CUDA
runtime. All three report themselves here; none of them require logging in.
