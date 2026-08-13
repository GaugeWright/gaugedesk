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

  # Everything else about Stop is proved against the scripted fake, whose hold is
  # a condvar the host itself releases. That never reaches the runtime: a real
  # interrupt goes host → `HostCancellationHandle::request` → a durable
  # cancellation request on an independent store connection → the kernel's driver
  # loop → the provider delegate's own cancelled terminal. Only a real turn
  # exercises the last two, and the last one is the provider actually stopping
  # when it is told to.
  #
  # The prompt is sized so an unstopped turn runs far past the assertion window,
  # and its closing marker is what makes the stop provable rather than assumed:
  # a turn that reached the end would have said DONE.
  #
  # Timing and a missing marker are necessary but not sufficient against a real
  # provider: a rate limit, a dead transport, or a turn that finished early all
  # look the same from outside. So the cancellation is asserted on its own
  # receipt, the one the engine reaches for the interrupt leg alone.
  Scenario: a real turn stops when it is asked to
    Given a new engagement
    When I start tasking the agent with "Write the numbers 1 to 400, each on its own line with a short sentence about it, into count.txt. When the file is complete, reply with exactly DONE."
    Then the agent is working
    When I stop the turn
    Then the stop is receipted as a cancellation
    And the real turn ends within twenty seconds
    And the agent never says "DONE"
    And the composer is ready to send again
