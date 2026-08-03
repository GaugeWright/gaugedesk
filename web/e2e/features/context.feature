@transport
Feature: Context ingestion

  As a user I can open a folder of context into the engagement, so the agent
  has reference material; the ingested files are committed and show in the diff.

  Scenario: attach a folder of context
    Given a new engagement
    When I attach the context folder "/home/jack/code/gaugedesk/plugin"
    When I open the "diff" tab
    Then the diff shows "gaugewright-plugin.ts"

  # desktop-native-context-production-client
  @transport
  Scenario: the desktop folder picker ingests a local path through the shipped client
    Given a new engagement
    When I reload as the desktop app and add the repository plugin folder
    When I open the "diff" tab
    Then the diff shows "gaugewright-plugin.ts"
