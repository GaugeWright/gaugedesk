@transport
Feature: Round 10 — honest improve-chat vocabulary, a legible status, clearer review chrome

  The round-10 review found the keep/review surface borrowing work-chat language
  ("kept into the shared copy") verbatim inside an improve chat — a category error,
  since improving a method changes something reused everywhere, not one project's
  copy; the chat status moved into the selected navigation row while the chat
  lane gained a single options menu; two adjacent "1 file" counts in
  the changes header that read as the same thing; and a method's reach labelled with
  the mild implementation word "placed in". These scenarios lock in the fixes.
  (The renderer-freeze fix — a ResizeObserver feedback loop in the diff panel — is
  structural and verified by typecheck/build; there is no DOM assertion for "the
  compositor no longer wedges".)

  Scenario: the chat lane keeps only one options button
    Given a new engagement
    Then the chat run state reads "Ready"
    And the chat lane has one options button

  Scenario: the changes header has no hidden runtime-config disclosure
    Given a new engagement
    When I task the agent with "make a change"
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the review offers no internal-file toggle
