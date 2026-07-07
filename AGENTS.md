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
`ToolCallDetail`, `CommitInfo`, enums, annotations, push envelopes, the `License` surface. The source of
truth every backend produces and every client consumes. Extracted from peasant's `pkg/schema` (peasant#114);
**the swap LANDED 2026-07-07** — the standalone public module is now the single contract both consumers
import (peasant `go.mod` + village `backend/go.mod` pin **`v0.1.0-rc2`**, specs `0.4.0`), the nested
`pkg/schema` is deleted, and village serves AND enforces the spec FROM the module (served ≡ enforced,
un-driftable). The cross-repo `vendorHash` / private-module-auth tax (peasant#119) is structurally dead.
**rc numberings — disambiguate on every read:** peasant product releases (`v0.1.0-rc2`), the schema
MODULE's own tags (`v0.1.0-rc1` + `v0.1.0-rc2`, both published prereleases), and "rc3" = the
(now-complete) harmonization epoch's name (not a tag). The extraction+harmonization beads record is
archived in the OLD workspace (`~/dev/agent-data-leverage/.beads`, prefix `unified-schema`,
supersede-closed) — read-only provenance.
⚠️ **Post-swap ceremony (now in effect):** a contract change is its own schema-repo PR + tag BEFORE the
consumer PRs that re-pin it (stated in both peasant + village AGENTS.md).
**Where to contribute:** `schema/develop` (Go source: `local_api.go`, `metadata.go`, `types.go`,
`annotation*.go`, `CHANGELOG.md`; the spec regen + freshness/immutability gates live here now — no longer
in peasant). The TS port (`@peasant-labs/types`) has **drifted** from the Go — trust the Go; the durable
fix is OpenAPI→TS codegen (#125/#126).

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
`internal/api` (the `session_detail` WS), `internal/store` (SQLite, `session_commits`), `pkg/` (`redact`
et al.; the `schema` module was extracted out — peasant now imports `github.com/peasant-labs/schema`),
`web/` (consumes transcript-browser). Owns the deferred backend wire work
(git cluster → peasant#143; scorecard medians). **Licensing surfaces (landed):** push
(`--license` flag / `push.license` config / FTUE page) and pull (V38 persists the served license;
all four `village` CLI surfaces display it); SQLite carries TWO closed-set CHECK mirrors of the license
menu (`sessions`/V37 + `pulled_transcripts`/V38) whose tests derive accept-sets from `schema.AllLicenses`
— widening the menu goes red until ONE migration rebuilds BOTH tables (SQLite cannot ALTER a CHECK).

### village → Go backend + JS frontend (full-stack app)
**Role:** the transcript **commons** (registry + access control + discovery over Postgres/S3;
`village/develop` has `backend/` + `frontend/`, `go.work`, `docker-compose`). Consumes the schema
contract as the ENFORCER (validates inbound publishes against the pinned spec). Fairtrade UI: landed.
**Transcript licensing + governance (landed, village#26):** CC license menu on publish/PATCH, a
**fail-closed trigger-written governance audit** (`app.actor_id` GUC; append-only audit table), and the
**un-license irrevocability gate** (a granted license can never be cleared via the app; 400).
**Where to contribute:** **read `village/develop/AGENTS.md` + `CLAUDE.md` first**, then the two deep
references: `TESTING.md` (the comprehensive testing strategy incl. the governance-era fixture/teardown
rules) and `docs/database-invariants.md` (migrations, triggers, the `app.*` GUC registry, audit model —
changes to any of those update that doc IN THE SAME COMMIT).

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
- **Licensing:** the menu is owned by the contract (`schema.AllLicenses`: `CC0-1.0`/`CC-BY-4.0`/
  `CC-BY-SA-4.0`) → village ENFORCES it (publish/PATCH + the governance audit) → peasant mirrors it
  in its two SQLite CHECKs and displays it end-to-end. **The canonical widening procedure is village
  `AGENTS.md` → "Adding a license" (the 10-step cross-repo table); peasant's twin section defers to it
  by name.** Licenses form a PARTIAL order (no rank, no computed meet); un-licensing is blocked
  app-side (CC grants are irrevocable). Followup ledgers: peasant#151 ⇄ village#29 (twins).

## Conventions
- **Branches / worktrees:** a feature worktree is named `<primary-repo>-<issue#>--<semantic-commit>--<descriptive-name>`, where the *primary repo* is the one the change centers on. A cross-repo epoch reuses that one name across **every** participating repo's worktree — e.g. the fairtrade-adoption work uses `fairtrade-1--breaking--adopt-fairtrade-design-system` in fairtrade, peasant, **and** village (`fairtrade-1` = GitHub issue #1 in the primary repo, fairtrade; sibling issues are peasant#142 / village#27).
- **Beads/pasture:** `bd` from this root (prefix `plabs`); the 12-phase epoch protocol.
- **Landing:** squash the epoch branch → `merge --no-ff` into the repo's **default** branch (`develop` for
  peasant/village, `main` for fairtrade/transcript-browser). On peasant/village, `main` advances only on a release.
- **After a PR merges, immediately sync the local default-branch worktree** — `git -C <repo>/develop pull`
  (or `<repo>/main` for fairtrade/transcript-browser). The local `develop`/`main` worktree does NOT
  auto-update on a remote merge, so any later feature worktree branched from it would start behind origin
  and re-introduce already-merged drift/conflicts. Then clean up the landed work: remove the merged feature
  worktree (`git worktree remove`) and delete its remote branch. Verify a merge state against GitHub
  (`gh pr view <n> --json state,mergeCommit`), not a possibly-stale local ref.
- **No git hooks** (hard rule). Nix devShell via `flake.nix`/direnv.
- **Generated files are never hand-merged.** On conflict (sqlc output, schema-gen goldens, lockfiles):
  merge the SOURCE (the `.sql` query / the Go types / the manifest), keep the target branch's generator
  config, and RE-RUN the generator — the committed output must be byte-identical to fresh codegen under
  the pinned generator version (verify with a zero-diff regen). Proven in the licensing epoch's
  merge wave (the sqlc `groups.sql.go` conflict; regen verified zero-diff by two reviewers).
- **Release tooling is duplicated across peasant + schema** (release-guard, release-pr/release
  workflows, `scripts/update-nix-vendor-hash.sh`) **and has drifted twice** — the base64-`/` perl bug
  was fixed independently in each copy weeks apart (schema 2026-06-20, peasant#154 2026-07-06), and the
  approval-gate deferral likewise landed in schema first and peasant only at #156. When touching one
  copy, diff the other.
- **The release-PR maintainer-approval assertion is deferred to the public flip** in BOTH peasant and
  schema (single active maintainer + GitHub's no-self-approval = unsatisfiable; the guard code +
  tests remain live). Re-enable it alongside branch protection at the flip — it's on **peasant's**
  runbook §6 checklist (the schema repo's runbook still has NO public-flip section — mirroring that
  checklist item there is an open followup; the rc3 epoch did NOT unify the approval gate).
- **Post-swap contract ceremony (IN EFFECT since the rc3 swap landed 2026-07-07):** a contract change is
  its own schema-repo PR + tag BEFORE the consumer PRs that re-pin it — stated in both peasant + village
  AGENTS.md checklists.
- **Shipped-artifact hygiene — WORKER-PREVENTED, reviewer-backstopped:** NO internal task taxonomy — `plabs-*` Beads IDs, `SLICE-N` / `W*-*` slice names, `LIP-N`, leaf-task IDs, or phase/epic codenames (`Wave 1`/`Wave-2`, `defer-2`, `PROPOSAL-N`) — in shipped **code, comments, docs/READMEs, OR commit messages**. Describe everything by substance (what the code does / why). **Prevention is the WORKER's job, not the reviewers':** never write internal tracking terminology into shipped artifacts in the first place, and **before reporting a slice complete, self-grep your changed files and scrub any hit** — e.g. `git diff --name-only <base>..HEAD | xargs grep -nE 'plabs-|SLICE-|W[0-9]+-|\bLIP-|Wave[ -]?[0-9]|defer-[0-9]|PROPOSAL-|\bTB\b'`. This is a mandatory pre-report gate so reviewers never spend cycles on expensive hygiene audits. The reviewer grep + the clean landing-squash message remain only as a **backstop**, not the primary catch. (`.tb-*` CSS selectors are real DOM names, not the taxonomy token — don't flag them. Pre-existing leaks from prior repo development are out of scope unless the user asks to clean them.)
- **Do not delete real prior-version functionality just because the persistent chrome changed.** If a route or component still serves a real user flow, default to soft-retaining it as a deprecation candidate and keep every production evidence exit that depends on it working. Only delete genuinely dead scaffolding, never-shipped experiments, or orphan wiring. If it is unclear whether something is real user-facing functionality, surface the decision before removing it.
- **Production exits must be tested on the mounted production path.** Tests against dormant legacy components are not enough. If a retained route exists because a current surface links to it, test the current mounted surface action and assert the actual navigation or callback users trigger.
- **Shared shell visual gates compare canonical demo to current app.** For fairtrade adoption SxS artifacts, the left/reference side should be a screenshot of the fairtrade in-use demo and the right side should be the current consuming app. Do not compare app-generated baselines to the app unless that is explicitly the regression target.
- **"Shell" means chrome plus mounted body, not a nav strip.** A shell screenshot must include persistent product header, section navigation, active-section state, route/view wiring, and representative body content for the mounted surface. Gates should fail closed when either side is missing or blank so they cannot pass on chrome-only captures.
- **Graph app section order is canonical:** `analytics | changes | code map` (user-updated 2026-07-01, superseding the earlier `analytics | code map | changes`). Fairtrade owns the shared section registry (`GRAPH_APP_SECTIONS` in `src/ui/inuse/InUseShell.jsx`); consumers derive from it and fail loudly on unknown or unmapped section IDs rather than silently dropping sections.

## Review & UAT discipline — process gaps + fixes (codified 2026-07-01 after repeats slipped)
The user should NEVER be the backstop that catches a repeat finding or a design-system violation. These gaps recurred; the fixes are now mandatory:
- **The live in-use DEMO is the fidelity oracle — match it element-for-element; when the demo and the DS docs CONFLICT, match the DEMO** (user ruling, 2026-07-01). A documented DS invariant that the DEMO ITSELF violates (e.g. providers using a generic git-fork glyph instead of `<BrandMark>`; middot `·` separators the docs ban but the demo uses ~54×) is a **DS-cleanup FOLLOWUP** (a bug in the DS repo), NOT an adoption finding — file it, don't fix it in the adoption unless the user says otherwise. Flag app↔demo DIVERGENCES and genuine gaps (something the demo has that the app misses), not demo-faithful matches that happen to violate a doc.
- **Reviewers + orchestrator MUST still be design-system-literate before reviewing or eyeballing any fairtrade-adoption surface** — but read the DS's OWN docs to UNDERSTAND intent, canonical component usage, and to resolve AMBIGUITY (not to override the demo): `fairtrade-design-system/main/AGENTS.md` (hard invariants), `README.md`, `llm/DESIGN.md`, `llm/NEUROINCLUSIVE.md`, and `src/sections-react/*` (annotated component specs + philosophy). Enforce the DS **hard invariants** on every surface: **Atkinson Hyperlegible** (prose) + **Atkinson Hyperlegible Mono** (chrome/display/code), loaded via a `<link>` in the layout `<head>`, NEVER a remote `@import` (Next prod CSS drops `@import` → whole-app mono fallback; `font-import-guard.test.ts` must pass on the CONSOLIDATED/real build); **provider names lead with `<BrandMark name="…"/>`** (claude/gemini/openai/cursor/opencode), never a raw slug or generic glyph; **all-lowercase UI chrome** (never lowercase user content); **tabular numbers** on counts/durations; **radius 0**; **tokens only** (no hardcoded hex/px — `var(--amber)`, `var(--sp-4)`); **amber is a scarce accent**; **two themes, both WCAG-AA**; **16px body floor / mono-14 chrome**; **neuroinclusive defaults** (1.5 line-height, ≥24px hit targets, focus ring, reduced-motion); **no AI-slop / no em-dashes / no `>` prefixes except the nav active marker**. A surface that violates a documented invariant is a finding even if it "looks close."
- **Every user eyeball/UAT finding is recorded VERBATIM in beads AND carried forward as a standing regression checklist.** Do not let any finding go unrecorded. Every re-review AND the orchestrator's pre-eyeball visual-verify must walk the ENTIRE prior-finding checklist and confirm each item is closed on the CURRENT build. Reviewing a slice against only its own fix-spec, in isolation, is NOT sufficient — repeats slip that way.
- **Never work around a gate instead of fixing the finding, and never trust a mount-only gate.** Do not hide a flagged element from captures (`data-visual-exclude` and the like) instead of removing/fixing it. The real-build verify must assert the actual RENDERED thing — computed `font-family`, computed layout/position, `.gmp-`/`.cmg-` computed styles — because a whole surface can ship unstyled or wrong while a "mounted + served" gate stays green. Known-defect guards (font `<link>`, `.gmp-*` computed-style, etc.) must run on the CONSOLIDATED integration build, not just an isolated worktree.
- **Verify the live server/dist actually serves the worktree you think, BEFORE trusting any capture (build-provenance check).** A screenshot/gate is only as good as the bytes behind the port. Two real traps hit this epoch: (a) a dev server left running against a STALE worktree (serving old `fairtrade-village-manage` while the fix landed on `main`) → a capture read "still broken"/"already fixed" without being live; (b) **fairtrade-worktree topology is asymmetric — peasant's build resolves `fairtrade/main`, but village's build resolves `fairtrade/fairtrade-village-manage`** (per its `pnpm-workspace.yaml` + `build-fairtrade.mjs`), so "rebuild main's dist" is a NO-OP for what village actually ships. Before believing a capture: grep the served `dist/` for a string only the fix introduces, confirm which fairtrade worktree the app resolves, and rebuild+restart from THAT source. A "timing artifact" (auditor screenshots the pre-fix set between reports) is the same class of bug — recapture fresh + name the exact build under test.
- **Unconsolidated slices are invisible to a body-only audit — verify every lifted slice actually landed on the integration branch.** A surface can pass its element-for-element body audit while a whole slice was never consolidated (this epoch: V-EXPLORE and V-SHELL were lifted on standalone worktrees but never merged onto the village integration branch — the app still rendered the pre-lift bespoke explore + old Navbar). The orchestrator must, per app, enumerate the intended slices and confirm each is present in the built artifact (grep the real DOM for the lift's marker classes, check the Navbar/route wiring), not assume "reviewers accepted the body" == "the app is complete."

## Epoch execution model (agent roles & parallelism)
How the user runs a pasture epoch — the orchestrator MUST follow this:
- **OpenCode subagents:** use project `worker-mini` agents for implementation fixes when the user asks for mini-model workers, and `reviewer` agents for review waves. Their prompts must start by running `/worker` or `/reviewer` respectively. Do not use `aura-swarm` when the user explicitly asks for subagents.
- **Explorers** = backgrounded subagents (`run_in_background`). **Architect, reviewers, workers** = active *foreground* teammates (not background, not one-shot ephemerals).
- **Implementation runs as parallel slices.** Decompose for maximum concurrency. Slices MAY overlap in *files changed* as long as they touch **semantically / functionally distinct** parts — file overlap alone is NOT a reason to serialize.
- **One isolated worktree per worker**, branched off the integration branch, so parallel workers never clobber each other's trees.
- **Merge conflicts are the orchestrator's job**, not the workers'. When a worker wraps feature work, the orchestrator merges integration → the slice branch and resolves conflicts; ambiguous or confusing design choices are surfaced to the user.
- **Default model tier = Opus.** Spawn ALL agents — explorers, research, architect, reviewers, workers — with `model: opus` by default; use a cheaper tier ONLY when the user specifies it for a given task. (Supersedes any earlier Haiku-explorer / Sonnet-worker defaults.)
- **Reviewers are STANDING Opus teammates** (A = Correctness, B = Test-quality, C = Elegance; spawn with `model: opus` — do NOT inherit the agent-default tier): they PERSIST across **all** review waves in an epoch — plan review (Phase 4) AND code review (Phase 10) — re-tasked per wave, **NOT** retired between waves. The re-review rounds are Opus too. **Keep the team UP and pre-reading the relevant slices + grounding (URD/handoff/scratchpad/source) BETWEEN waves so they're warm before a review fires — prepare them ahead of need, do NOT spawn them reactively/cold on demand.** Plan review needs all three to ACCEPT; code review needs a clean 0/0/0 (fix-free) round before the gate clears.
- **Proposal numbering is per-epoch:** each epoch restarts at PROPOSAL-1 (and SLICE-1, etc.) — do NOT continue a prior epoch's global sequence. Revisions increment within the epoch (PROPOSAL-1 → PROPOSAL-2 …).
- **Review completed slices in ONE wave, not piecemeal.** When multiple slices finish, dispatch the standing reviewers over ALL currently-completed slices in a single coordinated review wave — accumulate the done batch rather than firing a separate review round as each slice trickles in. Per-slice verdicts + severity trees are still preserved (one wave ≠ one merged severity tree across slices); the "wave" is about batching the *dispatch/timing*, not collapsing per-slice granularity.

## Current state (2026-07-07)
- **Fairtrade adoption: LANDED** in peasant + village (fairtrade **0.0.6**, transcript-browser **0.0.3**,
  pnpm-only web toolchains; peasant#149/#150, village#28).
- **Transcript licensing: LANDED end-to-end** (village#26 + peasant#141/#152). The license contract now
  lives in the standalone schema module (below), NOT the retired nested `pkg/schema`.
- **peasant `v0.1.0-rc2` published** (prerelease, full gate chain green). The standing CGO-trio CI debt
  was FIXED in the cut: `internal/codegraph`'s TypeScript tree-sitter extraction is cgo-gated per the
  `redact.MaximumAvailable` pattern — preserve that gating.
- **rc3 schema harmonization: LANDED 2026-07-07.** The `0.4.0` licensing contract was ported into the
  standalone `github.com/peasant-labs/schema` module (tag + GitHub Release `v0.1.0-rc2`) and both
  consumers re-pinned to it (peasant#159/#160, village#30/#31); the nested `pkg/schema` is deleted and
  village serves+enforces from the module. See the schema-repo section above.
- Other open follow-ups: the fairtrade rollout followup epic, transcript-browser#5 (scorecard richness),
  peasant#143 (git cluster on the wire), the licensing ledgers peasant#151 ⇄ village#29, and the
  pre-existing internal-taxonomy leak in the public schema repo's `internal/contractgates/doc.go`.
  (Beads IDs in `.agents.local/`.)

## Visual / screenshot UI harness (design-system fidelity capture)
Each app repo carries a headless-Chrome/Puppeteer capture harness for design-system fidelity work: shoot a surface in **both themes**, shoot the fairtrade **demo** for the same surface, stitch them **side-by-side (SxS)**, and diff/eyeball against the demo (the demo is the fidelity oracle — see "Review & UAT discipline"). **Verify computed styles (`getComputedStyle`), not just pixels** — close-value token pairs (`--surface` vs `--canvas`, `--ink-2` vs `--ink-3`) are indistinguishable in a scaled PNG.

**Locations:** village `frontend/scripts/visual/` · peasant `web/scripts/visual/` · fairtrade `scripts/`. Capture outputs go to `review-capture/` (untracked, local-only) or `/tmp` — **never commit per-round proof PNGs**; only the `baseline/` regression references are tracked.

**Core primitives** (~7 — currently duplicated per-surface AND per-repo; consolidation is a tracked followup):
| primitive | what it does | examples |
|---|---|---|
| **boot** | start the app server (dev, or the real binary) on a fixed port | `boot-village`/`boot-peasant`/`boot-explore`, `manage-boot-village` |
| **mock** | fake backend REST/auth so surfaces render deterministic fixtures | `mock-rest.mjs`, `mock-rest-explore.mjs` (adds `/auth/me`+`/auth/orgs` for authed surfaces) |
| **shoot** | headless screenshot per surface × theme | `{surface}-shoot.mjs`; fairtrade `shoot`/`shootdemo`/`shootmanage` |
| **stitch** | compose demo↔app into one SxS image | `stitch-sxs.mjs`, `manage-stitch-sxs.mjs` |
| **diff** | regression pixel-diff vs a committed baseline | `png-diff.mjs`; fairtrade `imgdiff.mjs` |
| **probe** | `getComputedStyle` assertions on the live DOM — the definitive token check | `probe-village`/`probe-peasant`/`probe-explore` |
| **gate** | pass/fail wrapper | `surface-gate.mjs`; fairtrade `check-surface-gate.mjs`; peasant `shell-nav-gate.mjs` |

**Workflow:** boot (+mock) → shoot the app surface + the demo (both themes) → stitch SxS → eyeball vs demo + probe computed styles + diff vs baseline.

**Discipline (non-negotiable):** always **verify build provenance before trusting a capture** — grep the served `dist`/`out` for a string only the fix introduces, and confirm which fairtrade dist the app resolves (a stale server or wrong worktree silently invalidates a shot; see the build-provenance rule above). Both apps resolve fairtrade via a pnpm `workspace:*` dev-link to `fairtrade-design-system/main` (swaps to a published `^0.0.x` range at landing). When pointing a human at captures, give the **full absolute path with `{...}` brace alternatives** for the theme/surface/demo-app-sxs axes.

**Pending (tracked followup):** collapse the ~58 duplicated scripts into ONE shared parameterized toolkit (`boot/shoot/stitch/diff/probe/mock/gate × --repo/--surface/--theme`) so a new surface is a config entry, not a new script.

*(Ephemeral beads task IDs for these followups are NOT checked in — they live in the gitignored polyrepo-root `.agents.local/` sidecar.)*
