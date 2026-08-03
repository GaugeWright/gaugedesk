@transport
Feature: Round 10 — honest improve-chat vocabulary, a legible status, clearer review chrome

  The round-10 review found the keep/review surface borrowing work-chat language
  ("kept into the shared copy") verbatim inside an improve chat — a category error,
  since improving a method changes something reused everywhere, not one project's
  copy; the per-chat status badge shrunk to a 10px grey whisper while it's the one
  signal that answers "do I need to do something?"; two adjacent "1 file" counts in
  the changes header that read as the same thing; and a method's reach labelled with
  the mild implementation word "placed in". These scenarios lock in the fixes.
  (The renderer-freeze fix — a ResizeObserver feedback loop in the diff panel — is
  structural and verified by typecheck/build; there is no DOM assertion for "the
  compositor no longer wedges".)

  Scenario: an improve chat's keep button speaks method terms, not project terms
    Given the workbench is open
    When I create an edit chat under the archetype "Default"
    And I request review for the next change
    And I task the agent with "make a change"
    And I open the "diff" tab
    Then I see the button "save to the archetype"
    And I do not see the button "keep this work"

  Scenario: a work chat's keep button still reads "keep this work"
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    And I open the "diff" tab
    Then I see the button "keep this work"

  Scenario: the per-chat status badge is a legible review call-to-action
    Given a new engagement
    Then the chat status badge reads "Ready"
    And the status badge text is at least 12px

  Scenario: the changes header has no hidden runtime-config disclosure
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the review offers no internal-file toggle
