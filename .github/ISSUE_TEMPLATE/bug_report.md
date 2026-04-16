---
name: "Bug Report"
description: "Report a bug or unexpected behavior"
title: "bug: <short description>"
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to report a bug!
  - type: input
    id: version
    attributes:
      label: Security Shield Version
      description: What version of the plugin are you running?
      placeholder: "e.g., 1.1.0"
    validations:
      required: true
  - type: input
    id: openclaw-version
    attributes:
      label: OpenClaw Version
      description: What version of OpenClaw are you using?
      placeholder: "e.g., latest, 0.x.x"
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      description: How can we reproduce the issue?
      value: |
        1. ...
        2. ...
        3. ...
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
      description: What did you expect to happen?
    validations:
      required: true
  - type: textarea
    id: actual
    attributes:
      label: Actual Behavior
      description: What actually happened?
    validations:
      required: true
  - type: textarea
    id: context
    attributes:
      label: Additional Context
      description: Configuration, logs, or other relevant information.
