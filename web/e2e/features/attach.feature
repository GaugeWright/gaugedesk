@transport
Feature: Message attachments

  The composer's paperclip clips file(s) to the message being composed: text files
  inline into the turn, images ride along as native WhippleScript resources (message-scoped,
  no workspace ingest). It is distinct from the durable Files-bar upload (context).

  Scenario: attach a text file to a message
    Given a new engagement
    When I attach the file "notes.txt" containing "hello from attachment"
    And I task the agent with "summarize the attachment"
    Then the transcript echoes my message "hello from attachment"
    And the composer has no pending attachments

  Scenario: attach an image to a message
    Given a new engagement
    When I attach a PNG image "screenshot.png"
    Then the composer shows an image attachment "screenshot.png"
    When I task the agent with "describe the screenshot"
    Then the run phase is "Completed"
    And the composer has no pending attachments

  Scenario: extract an Office document in the browser
    Given a new engagement
    When I attach a DOCX document "sample.docx"
    And I task the agent with "summarize the Word document"
    Then the transcript echoes my message "hello from Word"
    And the composer has no pending attachments

  Scenario: extract a PDF in the browser
    Given a new engagement
    When I attach the PDF document "report.pdf" containing "hello from PDF"
    And I task the agent with "summarize the PDF"
    Then the transcript echoes my message "hello from PDF"
    And the composer has no pending attachments
