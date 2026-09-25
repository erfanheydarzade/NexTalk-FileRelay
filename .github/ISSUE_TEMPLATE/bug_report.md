---
title: "Bug Report"
labels: ["bug", "triage"]
body:
  - type: textarea
    id: description
    attributes:
      label: Description
      description: "A clear and concise description of what the bug is."
    validations:
      required: true
  - type: textarea
    id: steps
    attributes:
      label: Steps To Reproduce
      description: "Steps to reproduce the behavior."
      value: |
        1.
        2.
        3.
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
      description: "What did you expect to happen?"
    validations:
      required: true
  - type: textarea
    id: actual
    attributes:
      label: Actual Behavior
      description: "What actually happened?"
    validations:
      required: true
  - type: textarea
    id: environment
    attributes:
      label: Environment
      description: "OS, Go version, FileRelay version."
    validations:
      required: false
  - type: textarea
    id: logs
    attributes:
      label: Relevant Logs / Stacktrace
      description: "Paste any relevant error output here."
