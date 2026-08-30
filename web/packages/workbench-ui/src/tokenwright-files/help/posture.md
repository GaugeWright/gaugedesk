# Server posture

TokenWright's security rests on an arrangement rather than on a product: the
management surface reachable only through a relay that holds no key and that the
box dials out to, and the model surface listening on loopback and — when direct
access is on — a WireGuard interface and nothing else. That arrangement is easy
to check and easy to erode. Someone opens a port to debug something. A firewall rule outlives its
reason. Security updates stop applying because nobody was watching. None of that
announces itself.

This document is the box saying what it currently is, so drift shows up here
instead of in an incident.

## What counts as a finding

A finding is a live problem, never a note about something normal. A box in good
order has an empty findings table — which is why the passed-check count is shown
beside it, so an empty table cannot be confused with nothing having run.

**Critical** means an attacker on the network can probably reach something.
**Warning** means a real weakness that needs a decision, not necessarily today.
**Advisory** means a hardening step that is worth doing and is not urgent.

## The listener table is the important one

Every listening socket on the box appears there, whether TokenWright put it
there or not. Two exposures are legitimate: `loopback`, and `wireguard` for the
model surface you offer your own tools. Anything `private` or `public` is
reachable from an ordinary network, and `expected: false` means the package did
not create it — that combination is the one to act on.

Inbound firewall allow rules are counted beyond the WireGuard listen port, and
the correct number of those is zero. The relay dials out, so nothing else needs
to be let in.

## What this cannot tell you

The box is reporting on itself. A host that has actually been compromised can
report whatever it likes, and no check running on that host changes it. This
document narrows the window in which a misconfiguration goes unnoticed; it is
not evidence that the box is uncompromised.

For that reason the audit log's head is anchored off-box. A compromised host can
rewrite its own history and re-sign it, but it cannot retract a head already
published elsewhere — so the contradiction survives even when the box's own
account of itself does not.

## Checking the trail against something the box cannot reach

**Anchored off-box** is the number that matters on this page. Entries beyond it
are only as trustworthy as this box, because the box holds the key that signs
its own head — it can rewrite its log and re-sign a head that is perfectly
consistent.

What it cannot do is retract a head your Home already recorded. So the check is:

1. Take an anchor your Home holds — a count and a head it wrote down earlier.
2. Read the box's trail up to that count.
3. Hash-walk to the entry at that count and compare it to the head you recorded.

If they differ, this box's history no longer matches something written down
elsewhere. There is no innocent cause: entries are append-only, so a head that
was true once stays true.

**Chain verified** on this page is a weaker claim, and it is worth knowing why.
It says every link held when the box last walked its own log, which catches an
edit, a reorder, and a deletion — by anyone but the box itself.
