@transport @enterprise-composition
Feature: Authenticated Panel authors keep draft and frozen preview custody

  Scenario: copy, edit, reload, and retire isolated author previews
    Given a controlled authenticated Panel author is using the real Home
    When the author copies a work Agent as a Panel through the Workshop
    And the author saves and reloads the Panel contract
    And the author previews both the frozen placement and its newer draft
    Then replacing and deleting previews preserves the project and authoring source
    And another admitted author and an unsigned caller cannot author that Panel
