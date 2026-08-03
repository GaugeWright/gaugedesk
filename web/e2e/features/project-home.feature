@transport
Feature: Project Home rollup panel (UX-2)

  A project's home panel summarises the project from data (INV-5): its audit rollup
  (placements / chats / events) and its recent runs and outputs-under-review, derived
  server-side via GET /projects/:id/home. Opened from the project's "project home…"
  context-menu entry; the id comes from context, never typed.

  Scenario: a project with a placement shows its at-a-glance rollup
    Given the workbench is open
    When I create a project named "rollup-co"
    And I open project home for project "rollup-co"
    Then the project-home panel is open
    And the project-home panel shows at least 1 placement
