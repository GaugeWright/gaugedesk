Feature: Placement version upgrade (UX-9, ADR 0063)

  Publishing a new version of an archetype gives its placements an "upgrade
  available" notice; the upgrade is manual by default — the placement stays on
  its version until taken.

  # A deliberately-placed archetype shows as its own node; publishing a new version of
  # it offers that placement an upgrade. (The project's built-in general placement is
  # hidden plumbing, so upgrade notices surface on the placements you explicitly added.)
  Scenario: publishing a new version offers a placement upgrade
    Given the workbench is open
    When I create a project named "site"
    And I place an archetype on the project "site"
    And I publish a new version of the archetype "Default"
    Then the placement on "site" shows an upgrade is available
    When I upgrade the placement on "site"
    Then the placement on "site" is up to date
