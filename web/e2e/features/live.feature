@transport @live-provider
Feature: Real agent end-to-end (opt-in)

  The cases where the real model's behavior drives the app: the agent actually
  uses a tool to create a file. Opt-in only (WhippleScript + real model, costs tokens, slow) —
  run with `npm run e2e:live`, excluded from the default suite.

  Scenario: the real agent creates the requested file
    Given a new engagement
    When I task the agent with "Create a file called e2e-live.txt containing exactly the word live and make no other changes. Then reply done."
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the diff shows "e2e-live.txt"
