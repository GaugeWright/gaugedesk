@transport
Feature: On-ramps and plain language (round 1)

  A brand-new project must never dead-end: it comes with a built-in general placement
  (implementation detail, never shown), so you just start chatting in the project — no
  "place a method first" step and no placement node to understand. The chat surface
  speaks plain language — a status badge you can read at a glance and "keep this work"
  rather than admit/promote/merge jargon.

  Scenario: a fresh project is immediately usable — just create chats
    Given the workbench is open
    When I create a project named "onramp-co"
    Then I see the project "onramp-co"
    When I start a chat in project "onramp-co"
    Then the run phase is "Init"
    And project "onramp-co" shows a chat

  Scenario: an open chat shows a plain-language status badge
    Given a new engagement
    Then the chat status badge reads "Ready"
