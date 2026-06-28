# peasant-labs — polyrepo guide for agents

`/home/minttea/dev/peasant-labs` is a **multi-repo workspace**: a set of independently-versioned git
repositories developed together. This file maps the five core product repos — what each is for, where to
find the details for contributing, and how they connect. (The root also hosts other repos — `bestiary`,
`reeve`, `provenance`, `website`, `zone`, `homebrew-tap`, … — not covered here.)

## Layout & shared infrastructure

- **git-worktree workflow per repo:** `<repo>/` is the worktree *host* (a throwaway `__dummy__`/`dummy`
  branch — never commit or push it). **The default branch is per-repo:** peasant + village use **`develop`**
  as the default/integration branch (the remote `HEAD` → `origin/develop`), with **`main` reserved for
  releases**; fairtrade-design-system + transcript-browser have only **`main`** (no `develop`). Feature work
  lives in additional worktrees `<repo>/<branch>`. Work in a feature worktree, not the host.
- **`flake.nix`** + `.envrc` (direnv) — the Nix devShell for the workspace.
- **`.beads/`** — shared Beads task DB, prefix **`plabs`**; run `bd` from this root. Work is tracked with
  the *pasture* 12-phase epoch protocol.
- **`llm/`** — cross-repo, LLM-facing planning docs (e.g. the fairtrade adoption playbooks).

## The core repos

### fairtrade-design-system → `@peasant-labs/fairtrade` (npm)
**Role:** the canonical **design system** + the shared **transcript UI components**. Single source of truth
for ALL theming + transcript-component decisions — consumers conform, never redefine canonical values.
**Exports:** `tokens.css` / `base.css` / `components.css` / `tokens.json` / `fonts.css`, `/icons`, and `/ui`
(React: design-system primitives + the lifted transcript components — composite `TranscriptViewer` +
primitives + graph node-visuals — plus the **one adapter** `adaptTranscript`, the sole wire-parse +
git-normalization boundary).
**Where to contribute:** `llm/DESIGN.md` + `llm/NEUROINCLUSIVE.md` (design language + a11y); `src/index.css`
(`@layer`ed `.ft-*` / `.txn-*` CSS); `src/ui/` (components) + `src/ui/transcript/` (`adapter.js` /
`adapter.parse.js`, `analytics.js`, `view-model.js`, `DATA-BINDING.md`, contract type-tests); the gates in
`package.json` / `scripts/` (`build:lib`, `validate`, `sbsmoke`, `shootdemo`, the parity oracle). Downstream
adoption guidance: `llm/fairtrade--{peasant,village}-adoption-plan.md`.

### schema → `github.com/peasant-labs/schema` (Go module)
**Role:** the canonical **data / wire contract** (Go) — `SessionDetailPayload`, `TurnDetail`,
`ToolCallDetail`, `CommitInfo`, enums, annotations, push envelopes. The source of truth every backend
produces and every client consumes. Extracted from peasant's `pkg/schema` (peasant#114); currently
releasing `v0.1.0-rc*`.
**Where to contribute:** `schema/develop` (Go source: `local_api.go`, `metadata.go`, `types.go`,
`annotation*.go`, `CHANGELOG.md`). The TS port (`@peasant-labs/types`) has **drifted** from the Go — trust
the Go; the durable fix is OpenAPI→TS codegen (#125/#126).

### transcript-browser → `@peasant-labs/transcript-browser` (+ `analytics`, `types`, `theme`)
**Role:** the reusable **transcript viewer** (pnpm monorepo). Renders a session via fairtrade's lifted
components fed by the one adapter; owns the **@xyflow graph engine** (fairtrade supplies node visuals only).
**Where to contribute:** `packages/browser` (`<SessionDetail>` → `adaptTranscript` → lifted components +
the graph engine), `packages/analytics` (single-session metrics: scorecard / phases / personal-medians),
`packages/types` (TS wire types — drifted; see schema), `packages/theme`, `examples/minimal` (integration
playground), `scripts/visual/` (the demo↔app visual-regression harness; pairs with fairtrade `shootdemo`).
Keeps back-compat re-exports so peasant compiles unchanged across the migration.

### peasant → Go backend + React web (the "engine room")
**Role:** ingests, indexes, and serves agent sessions; produces the `session_detail` wire (grounded in
schema). The web app embeds transcript-browser's `<SessionDetail>`.
**Where to contribute:** **read `peasant/develop/AGENTS.md` + `CLAUDE.md` first.** Key areas: `internal/ingest`
(the `CommitDetector`, pipeline), `internal/transcript` (`EntriesToTurns` folds entries → the wire),
`internal/api` (the `session_detail` WS), `internal/store` (SQLite, `session_commits`), `pkg/` (incl. the
`schema` being extracted), `web/` (consumes transcript-browser). Owns the deferred backend wire work
(git cluster → peasant#143; scorecard medians).

### village → Go backend + JS frontend (full-stack app)
**Role:** a consumer app (`village/develop` has `backend/` + `frontend/`, `go.work`, `docker-compose`).
Consumes the schema contract; adopting fairtrade's transcript UI in its own epoch.
**Where to contribute:** **read `village/develop/AGENTS.md` + `CLAUDE.md` first** (this guide's author has not
deeply explored village — defer to its own docs). Adoption: `village#27`, playbook
`llm/fairtrade--village-adoption-plan.md` (STEP 0 = map village's current transcript consumption).

## How they connect

```
                schema  (Go wire contract; @peasant-labs/types = drifted TS port)
                   │ defines the wire
        produced by ▼                              consumed/rendered by
   peasant backend ── session_detail ──►  transcript-browser  ◄── embed ── peasant web
   village backend ── (same contract) ──►  (SessionDetail +              village frontend
                                            @xyflow engine)
                                                   │ renders with components from
                                                   ▼
                              fairtrade-design-system  (@peasant-labs/fairtrade)
                              — also consumed directly by peasant web + village frontend
```

- **Data:** schema defines the wire → peasant/village backends emit `SessionDetailPayload` → the frontends
  render it.
- **Design/components:** fairtrade is the source of truth → transcript-browser, peasant-web, and village
  frontend consume its tokens + components (via `adaptTranscript`).
- **Composition:** peasant-web (and village) embed transcript-browser's `<SessionDetail>`.

## Conventions
- **Branches / worktrees:** a feature worktree is named `<primary-repo>-<issue#>--<semantic-commit>--<descriptive-name>`, where the *primary repo* is the one the change centers on. A cross-repo epoch reuses that one name across **every** participating repo's worktree — e.g. the fairtrade-adoption work uses `fairtrade-1--breaking--adopt-fairtrade-design-system` in fairtrade, peasant, **and** village (`fairtrade-1` = GitHub issue #1 in the primary repo, fairtrade; sibling issues are peasant#142 / village#27).
- **Beads/pasture:** `bd` from this root (prefix `plabs`); the 12-phase epoch protocol.
- **Landing:** squash the epoch branch → `merge --no-ff` into the repo's **default** branch (`develop` for
  peasant/village, `main` for fairtrade/transcript-browser). On peasant/village, `main` advances only on a release.
- **No git hooks** (hard rule). Nix devShell via `flake.nix`/direnv.
- **Shipped-artifact hygiene — WORKER-PREVENTED, reviewer-backstopped:** NO internal task taxonomy — `plabs-*` Beads IDs, `SLICE-N` / `W*-*` slice names, `LIP-N`, leaf-task IDs, or phase/epic codenames (`Wave 1`/`Wave-2`, `defer-2`, `PROPOSAL-N`) — in shipped **code, comments, docs/READMEs, OR commit messages**. Describe everything by substance (what the code does / why). **Prevention is the WORKER's job, not the reviewers':** never write internal tracking terminology into shipped artifacts in the first place, and **before reporting a slice complete, self-grep your changed files and scrub any hit** — e.g. `git diff --name-only <base>..HEAD | xargs grep -nE 'plabs-|SLICE-|W[0-9]+-|\bLIP-|Wave[ -]?[0-9]|defer-[0-9]|PROPOSAL-|\bTB\b'`. This is a mandatory pre-report gate so reviewers never spend cycles on expensive hygiene audits. The reviewer grep + the clean landing-squash message remain only as a **backstop**, not the primary catch. (`.tb-*` CSS selectors are real DOM names, not the taxonomy token — don't flag them. Pre-existing leaks from prior repo development are out of scope unless the user asks to clean them.)

## Epoch execution model (agent roles & parallelism)
How the user runs a pasture epoch — the orchestrator MUST follow this:
- **Explorers** = backgrounded subagents (`run_in_background`). **Architect, reviewers, workers** = active *foreground* teammates (not background, not one-shot ephemerals).
- **Implementation runs as parallel slices.** Decompose for maximum concurrency. Slices MAY overlap in *files changed* as long as they touch **semantically / functionally distinct** parts — file overlap alone is NOT a reason to serialize.
- **One isolated worktree per worker**, branched off the integration branch, so parallel workers never clobber each other's trees.
- **Merge conflicts are the orchestrator's job**, not the workers'. When a worker wraps feature work, the orchestrator merges integration → the slice branch and resolves conflicts; ambiguous or confusing design choices are surfaced to the user.
- **Default model tier = Opus.** Spawn ALL agents — explorers, research, architect, reviewers, workers — with `model: opus` by default; use a cheaper tier ONLY when the user specifies it for a given task. (Supersedes any earlier Haiku-explorer / Sonnet-worker defaults.)
- **Reviewers are STANDING Opus teammates** (A = Correctness, B = Test-quality, C = Elegance; spawn with `model: opus` — do NOT inherit the agent-default tier): they PERSIST across **all** review waves in an epoch — plan review (Phase 4) AND code review (Phase 10) — re-tasked per wave, **NOT** retired between waves. The re-review rounds are Opus too. **Keep the team UP and pre-reading the relevant slices + grounding (URD/handoff/scratchpad/source) BETWEEN waves so they're warm before a review fires — prepare them ahead of need, do NOT spawn them reactively/cold on demand.** Plan review needs all three to ACCEPT; code review needs a clean 0/0/0 (fix-free) round before the gate clears.
- **Proposal numbering is per-epoch:** each epoch restarts at PROPOSAL-1 (and SLICE-1, etc.) — do NOT continue a prior epoch's global sequence. Revisions increment within the epoch (PROPOSAL-1 → PROPOSAL-2 …).
- **Review completed slices in ONE wave, not piecemeal.** When multiple slices finish, dispatch the standing reviewers over ALL currently-completed slices in a single coordinated review wave — accumulate the done batch rather than firing a separate review round as each slice trickles in. Per-slice verdicts + severity trees are still preserved (one wave ≠ one merged severity tree across slices); the "wave" is about batching the *dispatch/timing*, not collapsing per-slice granularity.

## Current state (fairtrade transcript-component lift — landed 2026-06-25)
fairtrade **0.0.3** published (tagged `fairtrade-v0.0.3`); transcript-browser `main` consumes `^0.0.3`.
peasant + village adopt next (their `fairtrade-1--breaking--adopt-fairtrade-design-system` worktrees are
staged; playbooks in `llm/`). Open follow-ups: Beads epic `plabs-zgqo`, transcript-browser#5 (scorecard
richness), peasant#143 (git cluster on the wire).
