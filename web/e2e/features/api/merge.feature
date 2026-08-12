@api @contract
Feature: Merge to mainline (M2 WS-1 integrate)
  A clean turn settles itself into its shared line (ADR 0136 — work is held by
  line, not by change), and the mainline hop stays explicit and boundary-gated.

  The keep/reject pair that used to lead this file needed a candidate resting at
  "Clean", which a managed target no longer produces: `greedy_autosync` advances
  it at settle. That state still exists on an attached target, where the human
  keep is the ordinary path — but attaching one is a desktop dialog this suite
  cannot drive, so the coverage is not re-based here.

  Scenario: a clean turn advances itself and integrates into the mainline
    Given an engagement "mrg1"
    When the agent runs a turn in "mrg1"
    Then the merge of "mrg1" is "Advanced"
    When "mrg1" is integrated to the mainline
    Then the merge of "mrg1" is "Integrated"

  Scenario: sync pulls an integrated mainline change into another engagement
    Given an engagement "syncA"
    And an engagement "syncB"
    When the agent runs a turn in "syncA"
    And "syncA" is integrated to the mainline
    And "syncB" syncs from the mainline
    Then "syncB" reports it synced cleanly
