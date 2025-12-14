# Claude Code Agents - Quick Reference

## Overview

This project includes 13 specialized Claude Code agents designed to automate and improve the development workflow. Each agent focuses on a specific task and can be invoked either automatically or manually.

## Agent List

### 🔴 High Priority Agents

| Agent | Trigger | Description |
|-------|---------|-------------|
| **Git Guardian** | Automatic / `@claude git-check` | Prevents build artifacts and dependencies from being committed to the repository |
| **CI Failure Analyzer** | `@claude analyze-ci` | Analyzes CI pipeline failures and provides root cause analysis without making changes |
| **Pre-commit Validator** | `@claude validate` | Validates all changes against pre-commit hooks before pushing to ensure quality standards |
| **Workflow Debugger** | `@claude debug-workflow` | Debugs GitHub Actions workflow failures, permission issues, and configuration problems |

### 🟡 Medium Priority Agents

| Agent | Trigger | Description |
|-------|---------|-------------|
| **Coverage Guardian** | `@claude check-coverage` | Ensures new code maintains the 80% test coverage threshold requirement |
| **Commit Formatter** | `@claude format-commit` | Generates properly formatted conventional commit messages for semantic-release |
| **SonarCloud Pre-flight** | `@claude sonar-check` | Predicts SonarCloud quality gate results before pushing to main branch |

### 🟢 Nice-to-Have Agents

| Agent | Trigger | Description |
|-------|---------|-------------|
| **Secret Pre-scanner** | `@claude scan-secrets` | Performs comprehensive secret detection before commits to prevent credential leaks |
| **Auto-fix Post-mortem** | `@claude autofix-report` | Analyzes auto-fix workflow effectiveness and identifies improvement opportunities |
| **Dependency Validator** | `@claude update-deps` | Safely updates dependencies while ensuring all tests pass and CI remains stable |
| **Release Notes Generator** | `@claude release-notes` | Generates comprehensive release notes from conventional commits for GitHub releases |
| **Pre-push Validator** | Automatic | Validates all changes before pushing to ensure hooks pass and quality standards met |
| **Pre-commit Hook Validator** | Automatic | Runs all pre-commit hooks locally before allowing commits to proceed |

## Quick Start

### Most Common Use Cases

```bash
# Before committing code
@claude git-check          # Check for build artifacts
@claude check-coverage     # Verify test coverage
@claude validate           # Run pre-commit hooks

# Generate commit message
@claude format-commit

# When CI fails
@claude analyze-ci         # Understand the failure
@claude debug-workflow     # If it's a workflow issue

# Before merging to main
@claude sonar-check        # Check quality gates
@claude scan-secrets       # Paranoid security check
```

## Automatic Agents

Some agents activate automatically without manual triggering:

- **Git Guardian**: Activates before any `git commit` or `git push`
- **Pre-push Validator**: Runs before `git push`
- **Pre-commit Hook Validator**: Runs before `git commit`

## Documentation

For detailed documentation on each agent, see the individual agent files in `.claude/agents/` or the comprehensive [README.md](.claude/agents/README.md).

## Integration with Project Guardrails

These agents complement existing project guardrails:

- **Pre-commit hooks**: lefthook enforces formatting, linting, coverage
- **CI pipeline**: GitHub Actions validates builds and deployments
- **Agents**: Proactive assistance and analysis before issues occur

## Adding New Agents

To add a new agent:

1. Create `{agent-name}.md` in `.claude/agents/`
2. Follow the existing agent structure
3. Add to this summary and the main README
4. Test thoroughly before committing

---

*For complete documentation, workflows, and examples, see [.claude/agents/README.md](.claude/agents/README.md)*
