@api @contract
Feature: Export & review derive from the resource (M1)
  An output's egress/declassification is gated by the output resource's own
  stakeholders — the owners of the context it derived from — not by the caller.

  Scenario: exporting an output requires its stakeholders' consent
    Given an engagement "exp1"
    When a folder is opened as context in "exp1"
    And the agent runs a turn in "exp1"
    Then "exp1" has an "output" resource
    When export of the output in "exp1" is proposed
    Then the export's required consent includes "local-user"
    And the export remains requested before source consent in "exp1"
    When the owner consents to export in "exp1"
    Then export of "exp1" waits for target admission
    And raw scope lifecycle commands are absent for "exp1"

  Scenario: reviewing an output derives its required consenters from the resource
    Given an engagement "rev1"
    When a folder is opened as context in "rev1"
    And the agent runs a turn in "rev1"
    When review of the output in "rev1" is proposed
    Then the review's required consent includes "local-user"
    When the owner consents to the review in "rev1"
    Then the review of "rev1" clears and releases
