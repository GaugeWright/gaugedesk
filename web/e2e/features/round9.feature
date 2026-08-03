@transport
Feature: Round 9 — honest banners, legible search, one honest improve entry

  The round-9 review found the discard banner pinned over an unrelated, unchanged
  file; a filtered search that wouldn't tell you what matched and kept "+ project"
  rendered among results; a method-improve context menu that sold two modes that
  behave identically; the composer placeholder still leaking "archetype" / "the
  editor"; and rename opening a field that didn't select the existing name. These
  scenarios lock in the fixes.

  Scenario: live search highlights the matched substring in a surviving row
    Given the workbench is open
    When I create an archetype named "Mailer"
    And I search the facets for "mail"
    Then the matched text "Mail" is highlighted in the results

  Scenario: searching hides the "+ archetype" create affordance so it can't read as a hit
    Given the workbench is open
    Then I can create a new method
    When I search the facets for "Default"
    Then I cannot create a new method
    When I clear the facet search
    Then I can create a new method

  Scenario: the method-improve menu offers a single, honest improve entry
    Given the workbench is open
    When I open the context menu on the archetype "Default"
    Then the menu offers exactly one improve entry
    And the menu does not promise working alongside it live

  Scenario: the improve composer names the method and drops jargon
    Given the workbench is open
    When I create an edit chat under the archetype "Default"
    Then the composer placeholder does not mention "archetype"
    And the composer placeholder does not mention "the editor"

  Scenario: renaming a method selects the existing name so you can type over it
    Given the workbench is open
    When I start renaming the archetype "Default"
    Then the rename field has the existing name selected
