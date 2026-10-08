# signed-in-desktop-window
@transport @core
Feature: A signed-in desktop works its own Home

  The desktop window is served from its own origin and calls its control
  plane on loopback, so every request carrying the window's account session
  is preceded by a CORS preflight. Signed in, the shell hands the window a
  session for this Home (DR-0188) and the window works the signed-in
  account's projects with it. GaugeDesk 0.8.7 refused those preflights before
  CORS could answer them, and a signed-in person's first chat failed with
  "couldn't start a chat — Load failed". The rest of the suite drives the
  signed-out window, whose preflights pass, so it could not see that (WS-871).

  Scenario: a signed-in desktop's first message starts a chat
    Given the workbench is open
    And I am signed in to my GaugeWright account on this desktop
    Then the empty chat composer is ready
    When I task the agent with "draft a welcome note"
    Then the active chat is a work chat
    And the transcript shows "draft a welcome note"
    And the window presented its account session to start the chat
    And no request to the control plane failed

  Scenario: a signed-in desktop starts a chat in Personal and keeps talking
    Given the workbench is open
    And I am signed in to my GaugeWright account on this desktop
    When I start a new chat in Personal
    And I task the agent with "first task"
    And I task the agent with "second task"
    Then the transcript shows "second task"
    And the window presented its account session to start the chat
    And no request to the control plane failed
