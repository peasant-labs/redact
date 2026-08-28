# Changelog

## v0.1.4

Promotes v0.1.4-rc1 (no code change since the candidate).

## v0.1.4-rc1

### Changed
- A redacted path now keeps its last folder and replaces everything above it with one `<PATH>` placeholder: the project root `/home/alice/dev/app` becomes `/<PATH>/app`, and a project directly under the home folder gets the same form. Neither the account name nor a folder that leads to the project appears in a redacted path.
- The single-dash and double-dash slug forms of the same location follow the same rule: `-home-alice-dev-app` becomes `-<PATH>-app` and `--home--alice--dev--app` becomes `--<PATH>--app`.
- Titles use the same canonical form. A path under the project root becomes `/<PATH>/<project>/<relative>`; a home path outside the project keeps no folder name at all and becomes `/<PATH>`. The Windows form keeps its volume letter: `C:\Users\alice\dev\app` becomes `C:\<PATH>\app`.
- The replacement prefixes are derived from every value a session records - the working directory, the project root, the transcript file, the project slug and the host slug - instead of from the working directory alone. A session whose recorded locations have different shapes (a harness started in a subpackage of a monorepo, a project root outside the working directory, or two values written with different home conventions) no longer keeps the folders that lead to the project. A recorded transcript file now collapses to `/<PATH>/<file>`, and a transcript read from outside any home folder no longer switches the stage off for the other fields. A slug is read by the shape of the field that holds it, not by the account name inside it: a host slug always names a location, and a project name does when the value starts with the marker. An ordinary name that merely contains a `home` segment part way through (`some-home-page-widget`) is never rewritten. A slug whose account matches nothing the session recorded is exactly the case no other prefix covers, so it is redacted too.
- Values written by rule set 3.0.0 carry two placeholders (`/home/<USER>/<PATH>/app`). Redaction converges them on the canonical form, so one collection never mixes two shapes of the same path. The check is anchored at the start of the path, because the older form also contains the canonical placeholder.
- A Windows path in the metadata is redacted by the same stage now: `C:\Users\alice\dev\app` in the working directory or the project root becomes `C:\<PATH>\app`, keeping its volume letter like a redacted title does. Before, only the account name was replaced and the folders above the project survived.
- The two fallback rules for slugs in free text now fire on a machine-name-prefixed slug. `peasant_host_slug` required a non-word character before the marker, which a real host slug never has (`laptop--home--alice--`), so it could not fire on the values it exists for; it now accepts any position, and the double dash is not a shape an ordinary name takes. `claude_project_slug` additionally accepts the start of the text. The account name is replaced even when no folder chain is stripped.
- `RuleSetVersion` is `3.1.0`. The standard `unix_home_path` rule is unchanged: it still redacts other people's home paths that appear in transcript text.

## v0.1.3

Promotes v0.1.3-rc3 (no code change since the candidate). The three candidates below are folded into this release.

## v0.1.3-rc3

### Fixed
- A Claude Code turn that opens with `[Request interrupted by user` (with or without `for tool use]`, and whatever scaffolding follows) is the harness recording an interruption, not user prose. The title pipeline treats it as a whole injected turn (exported as `InterruptedRequestPrefix`).

### Changed
- Every fixture family in `testdata/title.yaml` now carries a required-name manifest (`requiredSimpleTitleNames`, `requiredDecoderMutationNames`, `requiredGenerateFromTurnsNames`, `requiredPolicyCompilationNames`), checked by one shared exact-membership helper; the last bare row counts are gone.

## v0.1.3-rc2

### Fixed
- A Claude Code turn that opens with `Another Claude session sent a message:` is inter-session mail, not user prose. The title pipeline now treats it as a whole injected turn (exported as `AgentMailPrefix`) and moves on to the next usable turn; a title can no longer read as that prefix line.

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
