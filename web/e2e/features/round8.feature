@transport
Feature: Round 8 — plain-language tool detail and legible fork lineage

  The round-8 review found that expanding a tool-call row revealed the raw
  `{"path":…}` JSON argument blob (the dev-speak earlier rounds scrubbed from the
  headers, just one level down), and that a forked chat sat as a flat sibling of
  its source — indistinguishable but for the "(fork)" suffix, with nothing showing
  it was a copy or what carried over. These scenarios lock in the fixes.

  Scenario: expanding a tool line shows a plain sentence, not raw JSON
    Given a new engagement
    When I task the agent with "draft a tagline for spring"
    Then the run phase is "Completed"
    When I expand the first tool line
    Then the first tool line is expanded
    And the expanded tool detail reads in plain language

  Scenario: a forked chat shows what it was copied from
    Given a new engagement
    When I switch to the "Projects" facet
    And I fork the first chat
    Then I see a forked chat
    And the forked chat shows it is a copy of its source

  Scenario: opening a fork explains the copy semantics on its empty transcript
    Given a new engagement
    When I switch to the "Projects" facet
    And I fork the first chat
    Then the chat shows it started as a copy with files but a fresh conversation
