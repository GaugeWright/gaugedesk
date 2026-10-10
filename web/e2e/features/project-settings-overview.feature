@transport
Feature: A project's at-a-glance summary (UX-2, Project Settings overview)

  Selecting a project row opens that project's Project Settings on its Overview,
  which names the project and links to each settings page with a summary drawn
  from the project's projection (INV-5): how many Agents are placed, how many
  work targets it has. Agents & placements lists each placement with its pinned
  version (experience/navigation.md, "The facet browser"; experience/admin-console.md,
  "Project Settings"). The project id comes from the selected row, never typed.

  Scenario: a project with a placement shows its at-a-glance rollup
    Given the workbench is open
    When I create a project named "rollup-co"
    And I place an archetype on the project "rollup-co"
    And I open project settings for project "rollup-co"
    Then the project settings overview names the project "rollup-co"
    And the project settings overview counts 1 placed Agent
    When I follow the project settings overview to "Agents & placements"
    Then project settings list 1 placed Agent with its pinned version
