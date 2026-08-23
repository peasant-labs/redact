# Changelog

## v0.1.2

### Fixed
- The title pipeline (`Generate`, `SimpleTitle`) now removes harness-injected markup before a title is derived: command wrappers (`command-name`, `command-message`; `command-args` is unwrapped), local-command blocks (caveat, stdout, stderr), task-notification, teammate-message, skill-body turns, Codex `environment_context`, and OpenCode `system-context`. Harnesses absent from the table keep their first turn verbatim.
- Empty text from `Generate` or `SimpleTitle` now means "this turn has no user prose; try the next user turn". A pipeline error means "unusable turn; never expose its raw text".

### Added
- `GenerateFromTurns(turns, ctx)` selects the first usable turn in order and reports skipped errors.
- Exported wrapper name constants (`Wrapper*`, `SkillBodyPrefix`) so consumers can share one markup catalog.
