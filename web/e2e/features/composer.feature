@transport
Feature: The composer's delivery controls

  ⏎ sends the draft wherever the mode points, and the primary button is the same
  act under the pointer. The two are one control: the destination menu opens on
  hover and lays the active mode's row *over* the button, so moving toward the
  other destinations never crosses an un-hovered gap and a click without moving
  still reaches the destination the button was offering.

  Every other feature drives the composer with ⏎ because that is cheaper and does
  not depend on hover choreography. This is where the pointer path itself is
  checked, so the overlay cannot quietly break without a test noticing.

  Scenario: the primary button sends the draft under the pointer
    Given a new engagement
    When I type "make a change" into the composer
    And I click the primary destination
    Then the run phase is "Completed"

  Scenario: the destination menu offers the other routes on hover
    Given a new engagement
    When I type "put this away for later" into the composer
    And I hover the primary destination
    Then the destination menu offers "stash"
    And the destination menu offers "fork"
