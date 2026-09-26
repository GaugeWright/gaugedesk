@transport
Feature: Context ingestion

  As a user I can open a folder of context into the engagement, so the agent
  has reference material; the ingested files are committed and show in the diff.

  Scenario: attach a folder of context
    Given a new engagement
    When I attach the context folder "plugin"
    When I open the "diff" tab
    Then the diff shows "gaugewright-plugin.ts"

  Scenario: drop a file onto Files
    Given a new engagement
    When I drop the file "source.txt" containing "workspace context" on Files
    Then the target workspace contains "source.txt"

  # desktop-native-context-production-client
  @transport
  Scenario: the desktop folder picker ingests a local path through the shipped client
    Given a new engagement
    When I reload as the desktop app and add the repository plugin folder
    When I open the "diff" tab
    Then the diff shows "gaugewright-plugin.ts"

  # streamed-context-upload-production-client
  @transport
  Scenario: a recording too large to buffer streams in through the shipped client
    Given a new engagement
    When I add a recording too large to buffer named "take.wav"
    Then the target workspace contains "take.wav"
