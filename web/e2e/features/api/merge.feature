@api @contract
Feature: Merge to mainline (M0 keep + M2 WS-1 integrate)
  A turn's diff is kept by admitting it (the standing ref advances), then integrated
  into the shared mainline through the boundary-gated WS-1 hop.

  Scenario: keep a turn's diff and integrate it into the mainline
    Given an engagement "mrg1"
    When the agent runs a reviewed turn in "mrg1"
    Then the merge of "mrg1" is "Clean"
    When the diff of "mrg1" is admitted
    Then the merge of "mrg1" is "Advanced"
    When "mrg1" is integrated to the mainline
    Then the merge of "mrg1" is "Integrated"

  Scenario: rejecting a turn's diff isolates the engagement
    Given an engagement "mrg2"
    When the agent runs a reviewed turn in "mrg2"
    Then the merge of "mrg2" is "Clean"
    When the diff of "mrg2" is rejected
    Then the merge of "mrg2" is "Rejected"

  Scenario: sync pulls an integrated mainline change into another engagement
    Given an engagement "syncA"
    And an engagement "syncB"
    When the agent runs a reviewed turn in "syncA"
    And the diff of "syncA" is admitted
    And "syncA" is integrated to the mainline
    And "syncB" syncs from the mainline
    Then "syncB" reports it synced cleanly
