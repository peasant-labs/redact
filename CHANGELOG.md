# Changelog

## v0.1.3-rc1

### Fixed
- The title pipeline now removes three more harness-injected wrappers, each grounded against a recorded session: Codex `recommended_plugins` (the plugin catalog) and `user_action` (the review-action envelope), and Claude Code `agent-message` (attributed inter-session mail). All three drop the whole block. OpenCode `<constraints>` and a user prompt that opens with `<h1>` are user prose and stay verbatim; both are pinned by fixture rows.

### Changed
- `testdata/title.yaml` now carries a `requiredCaseNames` manifest; the fixture loader asserts exact membership in both directions instead of a bare row count.

## v0.1.2

Promotes v0.1.2-rc1 (no code change since the candidate).

### Fixed
- The title pipeline (`Generate`, `SimpleTitle`) now removes harness-injected markup before a title is derived: command wrappers (`command-name`, `command-message`; `command-args` is unwrapped), local-command blocks (caveat, stdout, stderr), task-notification, teammate-message, skill-body turns, Codex `environment_context`, and OpenCode `system-context`. Harnesses absent from the table keep their first turn verbatim.
- Empty text from `Generate` or `SimpleTitle` now means "this turn has no user prose; try the next user turn". A pipeline error means "unusable turn; never expose its raw text".

### Added
- `GenerateFromTurns(turns, ctx)` selects the first usable turn in order and reports skipped errors.
- Exported wrapper name constants (`Wrapper*`, `SkillBodyPrefix`) so consumers can share one markup catalog.
