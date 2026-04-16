---
name: "Feature Request"
description: "Suggest a new feature or improvement"
title: "feat: <short description>"
labels: ["enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for suggesting a feature!
  - type: textarea
    id: problem
    attributes:
      label: Problem Statement
      description: What problem are you trying to solve?
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposed Solution
      description: Describe your proposed solution.
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives Considered
      description: What alternatives have you considered?
  - type: dropdown
    id: layer
    attributes:
      label: Affected Layer
      description: Which defense layer does this relate to?
      options:
        - "L1 — Input Guard"
        - "L2 — Security Context"
        - "L3 — Tool Approval"
        - "L4 — Security Baseline"
        - "General / Infrastructure"
