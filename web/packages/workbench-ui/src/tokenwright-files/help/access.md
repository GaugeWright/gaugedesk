# Access

Two questions this page answers: who can use this box, and where it answers.

## Pairing is the root of the rest

Every key on this page exists because a Home claimed this box. The claim
happened once, from a code printed on the box at first boot, and it is what
`paired-home` was minted by.

Unpairing is available from here and locally on the box, because each covers the
other's failure — this one when the box is unreachable is no help, and the local
one when the Home is gone. Either way the box forgets the Home, revokes every
key, and mints a new claim code that is printed on its console and returned by
nothing.

That means an unpair you did not intend is not undone from a browser: reclaiming
the box needs someone next to it. The same is true if the Home is lost without
unpairing first. It is a real lockout, and it is the deliberate one — a remote
way to reclaim a paired box is a remote way to steal one.

## Why keys are per client

A single shared secret makes every revocation a decision about everything. Cut
off an editor you no longer trust and the paired Home stops working too, so in
practice nobody revokes anything.

One key per client removes that. Name them after the thing that holds them —
`workstation-editor`, `ci-runner` — and each can be withdrawn alone.

## Declaring rather than commanding

You do not issue a key by pressing a button and naming it in a dialog. You add
the name to the declared list, and the box reconciles: it mints what is missing
and revokes what you removed.

That is the same shape as everything else the box does, and it means the list
survives a reboot without a second copy of the intent living somewhere in
systemd or a database that could disagree with it.

## The one time a secret appears

A key nobody can read is a key nobody can use, so a freshly minted one is shown
here — once.

It stays until you acknowledge it. Reading this page does not consume it, so you
cannot lose a key by opening the wrong tab, and acknowledging is a deliberate
act rather than a side effect. After that it is gone, and no part of the box can
produce it again. If you lose it, remove the name and add it back; you get a new
key, and the old one stops working.

The exception is `paired-home`. It is the key GaugeDesk itself uses, so removing
that name cuts off the surface you would remove it from. The check set refuses a
declared list without it.

## Reachability is not permission

The relay endpoint is somewhere the box **dials out to**. It is not an address
anything can connect to, and seeing it tells an attacker nothing they can use.

The direct base URL is different: it is a real address, reachable by anything on
your WireGuard interface. It still needs a key. Being able to reach the box has
never been sufficient to use it, and that is deliberate — a network you trust is
a weaker claim than a key you issued.
