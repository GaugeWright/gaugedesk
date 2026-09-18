Feature: Coming back from the provider opens the step that is left (LOGIN-3/4/5)

  A first-time Google sign-in used to end at a 403 — "this Google account is
  not linked" — because the consumer callback had only two answers for a
  verified subject, resolve or refuse, and a person with no account is neither.
  The callback now has a third: mint a one-time signup ticket and send the
  browser back to the WebAuthn origin carrying it, so the person finishes the
  owner path ADR 0146 section 1 requires rather than being turned away.

  This scenario exists because the client half of that shipped broken and
  nothing could have caught it. The card read `props.providerSignup` only
  inside `createSignal` initializers, which run once at construction — while
  the host is still claiming the ticket over the network. It typechecked, the
  Rust suite was green, the route tests passed, and the person came back from
  Google to the same email field they had left. There is no DOM test
  environment in this repository, and the signup e2e drives routes with `fetch`
  against a stub page without ever mounting the card, so the only way to gate
  this is to render the real thing.

  @ui-mocked
  Scenario: the card opens on the provider account step
    Given a signup ticket from the provider is on the URL
    Then the card opens on the provider account step
    And it shows the address the provider attested
