---
name: Unified issue template
about: Standard GitHub Pull Request template to facilitate professional PR descriptions
  for this and future updates.
title: ''
labels: ''
assignees: ''

---

# Description

Please include a summary of the change and which issue is fixed. Please also include relevant motivation and context.

- [ ] **Renaming**: Service renamed to `nvelox`.
- [ ] **Feature**: Modular Configuration (Supports `include: "conf.d/*.yaml"`).
- [ ] **Feature**: Advanced Logging (File-based, Level-based).
- [ ] **Documentation**: Updated README and added `nvelox.example.yaml`.

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

# How Has This Been Tested?

Please describe the tests that you ran to verify your changes.

- [ ] **Manual Test**: Verified config loading with split files.
- [ ] **Manual Test**: Verified log file creation and content.
- [ ] **Unit Tests**: `go test ./...` passed.

# Checklist:

- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
