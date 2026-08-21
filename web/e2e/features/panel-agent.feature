@transport
Feature: Panel agents belong to the Library and deploy through projects

  Scenario: author, preview, place, and reach deployment custody
    Given the workbench is open
    When I create a Panel agent named "Public intake"
    Then the Panel agent "Public intake" is in the Library
    When I preview the Panel agent "Public intake"
    Then its disposable public preview is open
    And the preview says it writes no production Inbox data
    When I close the Panel agent preview
    And I open settings for the Panel agent "Public intake"
    Then its Panel contract editor is open
    When I close the Agent settings
    And I create a project named "Customer site"
    And I place the Panel agent "Public intake" on project "Customer site"
    Then project "Customer site" has a Panel-agent placement without a new-chat action
    When I open deployment for the Panel agent in project "Customer site"
    Then deployment shows the frozen public contract
    When I open the deployment Inbox
    Then the project Inbox for "Customer site" is open
