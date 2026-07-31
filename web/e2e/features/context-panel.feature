Feature: Context sources panel (O-1)

  As a user I can see the context this chat is working with — the folders I
  attached and the method behind it — so the agent's reference material is legible
  at a glance, not invisible behind the "add files" button. The panel lists each
  source's kind and availability over the GET /resources projection; it never
  shows the payload (INV-10).

  Scenario: an attached folder appears as a context source
    Given a new engagement
    When I attach the context folder "/home/jack/code/gaugedesk/plugin"
    When I open the context sources panel
    Then the context sources panel lists a "context" source
    And the context source is marked "available"

  Scenario: the sources panel is empty before any context is attached
    Given a new engagement
    When I open the context sources panel
    Then the context sources panel shows no context sources

  # resource-access-production-client
  @transport
  Scenario: a resource owner requests and approves withheld context through the shipped client
    Given a withheld context source
    When I request access to the withheld context source
    And I approve access to the withheld context source
    Then the withheld context source is available
