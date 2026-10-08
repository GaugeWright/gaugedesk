@transport @core
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

  Scenario: the send button stays fully visible at a narrow laptop width
    Given a new engagement
    When the window is a narrow laptop size
    Then the send button is fully on screen

  Scenario: the composer stays pinned even with a long transcript on a short window
    Given a new engagement
    When the window is a short frame
    And I task the agent with "add a closing line"
    Then the send button is fully on screen

  Scenario: a long message wraps and grows without taking over the Chat panel
    Given a new engagement
    Then the message field wraps, grows, and stops at half the Chat panel

  Scenario: sending echoes my message immediately
    Given a new engagement
    When I start tasking the agent with "write a haiku about cats"
    Then the transcript echoes my message "write a haiku about cats"

  Scenario: the improve composer names the method and drops jargon
    Given the workbench is open
    When I create an edit chat under the archetype "Default"
    Then the composer placeholder does not mention "archetype"
    And the composer placeholder does not mention "the editor"
