@transport
Feature: Panel agents belong to the Workshop and deploy through projects

  Scenario: author, place, and reach deployment custody
    Given the workbench is open
    When I create a Panel agent named "Public intake"
    Then the Panel agent "Public intake" is in the Workshop
    When I open the Panel agent "Public intake"
    Then the Panel agent is open as the Workshop draft
    And its settings offer no way to try it
    When I open settings for the Panel agent "Public intake"
    Then its Panel contract editor is open
    When I close the Agent settings
    And I create a project named "Customer site"
    And I place the Panel agent "Public intake" on project "Customer site"
    Then project "Customer site" has a Panel-agent placement without a new-chat action
    When I open deployment for the Panel agent in project "Customer site"
    Then deployment shows the frozen public contract
    And deployment exposes publication and Inbox controls
    When I open the deployment Inbox
    Then the project Inbox for "Customer site" is open

  Scenario: a Panel placement opens its own settings
    Given the workbench is open
    When I create a Panel agent named "Number survey"
    And I create a project named "Survey site"
    And I place the Panel agent "Number survey" on project "Survey site"
    And I select the Panel-agent placement in project "Survey site"
    Then Panel Settings for "Number survey" is open with its management conversation
    When I open the Panel Settings page "Inbox"
    Then the Panel Settings Inbox says what a kept item becomes

  # The rest of the custody model (PANEL-7): what is previewed, published,
  # collected from a visitor and reviewed at the gate, against the loopback
  # edge fixture (`e2e/panel-edge.mjs`).
  Scenario: preview, deploy, collect a visitor's result, and review it at the gate
    Given the workbench is open
    When I create a Panel agent named "Survey intake"
    And I open settings for the Panel agent "Survey intake"
    And I set its Panel contract to collect results on the model "gpt-5.5"
    And I close the Agent settings
    And I try the Panel agent "Survey intake" in a preview chat
    Then a Panel preview chat is open that says what it does not exercise
    When I publish a new version of the Panel agent "Survey intake"
    And I create a project named "Survey office"
    And I place the Panel agent "Survey intake" on project "Survey office"
    And I open deployment for the Panel agent in project "Survey office"
    And I deploy it for the website "https://customer.example" paying with a new provider key
    Then the deployment "Survey intake" is live at the local edge
    When a visitor to "Survey intake" leaves the result "favourite number: 7"
    And I bring the deployment's results into the Inbox
    Then the deployment says 1 result arrived in the "Survey office" Inbox
    When I open the deployment Inbox
    Then the "Survey office" Inbox holds the visitor's result "favourite number: 7"
    When I keep the visitor's result
    Then the project gate has kept the visitor's result

  Scenario: a deployment from before project bindings is imported, never overwritten
    Given the workbench is open
    And the edge already serves "Legacy intake" from before project bindings
    When I create a Panel agent named "Legacy intake"
    And I open settings for the Panel agent "Legacy intake"
    And I set its Panel contract to the model "gpt-5.5"
    And I close the Agent settings
    And I publish a new version of the Panel agent "Legacy intake"
    And I create a project named "Legacy site"
    And I place the Panel agent "Legacy intake" on project "Legacy site"
    And I open deployment for the Panel agent in project "Legacy site"
    And I try to deploy it for the website "https://legacy.example" with the existing key
    Then the deployment is refused until it is imported
    When I confirm this Panel agent and project own it and import it
    Then "Legacy intake" is imported without anything changing at the edge
