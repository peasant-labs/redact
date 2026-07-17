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
- **Beads service boundary (hard rule): NEVER run `bd dolt start` or `bd dolt stop`.** If Beads reports
  that its Dolt service is unavailable or needs intervention, stop Beads work and let the user handle the
  service. Do not attempt a restart, shutdown, repair, or workaround that changes the service lifecycle.
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
import (peasant `go.mod` + village `backend/go.mod` currently pin **`v0.1.0-rc5`** — serving/enforcing
Village API `0.5.0` — while the module's current specs at **`v0.1.0-rc6`** are Village `0.6.0` /
Local API `0.4.0` / Types `0.3.0`, with all retired versions byte-frozen), the nested
`pkg/schema` is deleted, and village serves AND enforces the spec FROM the module (served ≡ enforced,
un-driftable). The cross-repo `vendorHash` / private-module-auth tax (peasant#119) is structurally dead.
**rc numberings — disambiguate on every read:** peasant product releases (`v0.1.0-rc2`), the schema
MODULE's own published prerelease tags (`v0.1.0-rc1` through `v0.1.0-rc6`), and the historical phrase
"rc3 schema harmonization" = the harmonization EPOCH's name, not a reference to the later tooling-only
schema tag `v0.1.0-rc3`. The extraction+harmonization beads record is
archived in the OLD workspace (`~/dev/agent-data-leverage/.beads`, prefix `unified-schema`,
supersede-closed) — read-only provenance.
⚠️ **Post-swap ceremony (now in effect):** a contract change is its own schema-repo PR + tag BEFORE the
consumer PRs that re-pin it (stated in both peasant + village AGENTS.md).
**Where to contribute:** `schema/develop` (Go source: `local_api.go`, `metadata.go`, `types.go`,
`annotation*.go`, `CHANGELOG.md`; the spec regen + freshness/immutability gates live here now — no longer
in peasant). **The schema module now also owns the generated TypeScript contract package
`@peasant-labs/schema`** (landed schema#29/#30, first shipped in tag `v0.1.0-rc6`, 2026-07-17): Hey API +
Zod generate the root types/runtime schemas from the Types OpenAPI catalog; `openapi-typescript` generates
the type-only `/local-api` + `/village-api` operation contracts; `/types` is a deprecated compatibility
re-export; nominal `ProjectHash` branding is `$ref`-anchored. **The package is PUBLISHED on npm**
(first cut `0.1.0-rc6`, 2026-07-17, public, dist-tag `next`; the committed manifest keeps
`0.0.0-development` + `private` as the local safety — the real version is stamped from the module tag at
publish time). **npm publication is being AUTOMATED into the release ceremony** (schema#32, in flight):
a `release.yml` npm-publish job behind the same guard → vendor-hash → contract-gates chain, authenticated
via npm Trusted Publishing (GitHub OIDC — NO token secret), bound to the `npm-publish` GitHub environment,
publishing rc tags under `next` and finals under `latest` with provenance attestation. The one-time
registrations (GitHub environment + npm Trusted Publisher, allowed action `npm publish` only) are
maintainer actions documented in the schema release runbook. The handwritten
`@peasant-labs/types` port is **deprecated — never add new wire definitions there**; migrating
transcript-browser/peasant-web onto the generated package (with a deprecated shim) is the open follow-up
(#125/#126 are thereby resolved at the schema end).

### transcript-browser → `@peasant-labs/transcript-browser` (+ `analytics`, `types`, `theme`)
**Role:** the reusable **transcript viewer** (pnpm monorepo). Renders a session via fairtrade's lifted
components fed by the one adapter; owns the **@xyflow graph engine** (fairtrade supplies node visuals only).
**Where to contribute:** `packages/browser` (`<SessionDetail>` → `adaptTranscript` → lifted components +
the graph engine), `packages/analytics` (single-session metrics: scorecard / phases / personal-medians),
`packages/types` (TS wire types — deprecated, superseded by schema's generated `@peasant-labs/schema`
package; the shim migration is the open follow-up), `packages/theme`, `examples/minimal` (integration
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
                schema  (Go wire contract + generated @peasant-labs/schema TS package;
                         @peasant-labs/types = deprecated handwritten port)
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

## Peasant data and UX invariants (current)

### Redaction: semantic category, activation level, and rendered label are separate axes

- **Semantic `pkg/redact.Category` values are** `secrets`, `pii`, `paths`, and `project`. They describe
  what a rule detects. Do NOT introduce a separate `CategoryGitContext`: git remotes, import paths,
  Docker refs, branch names, and CI project variables remain semantically `CategoryProject`.
- **Activation policy is independent.** `Rule.MinimumLevel` is optional: empty inherits the category's
  minimum; a populated value may only be a valid STRICTER level. `categoryMinimumLevel` remains the
  canonical category default. User patterns inherit their category default and do not expose their own
  activation override.
- **The three built-in git-context rules are the deliberate exception within `CategoryProject`:**
  `git_remote_https`, `git_remote_ssh`, and `git_branch_output` set `MinimumLevel: Maximum`. Therefore
  Standard keeps remote URLs and branch output; Maximum redacts them. This behavior is
  `pkg/redact.RuleSetVersion = 3.0.0` and landed in peasant#146 + schema `v0.1.0-rc5` + village#38.
- **Rendered consumer labels use public `pkg/redact.CategoryString`, never a private `WebCategory` or
  an `internal/redactcategory` mapping.** `Category.String() CategoryString` is the canonical rendering:
  `secrets → CREDENTIAL`, `pii → PII`, `paths → PATH`, `project → INTERNAL`. Raw storage tokens require
  an explicit conversion; rendered labels use `String()`.
- **Unknown categories fail closed.** Call `Category.Validate()` at trust boundaries. `String()` returns
  the zero `CategoryString` for an invalid category; it never falls back to `CREDENTIAL`. The server,
  generated mocks, and frontend must reject unknown or group/item-inconsistent categories rather than
  silently relabeling them. Use the `pkg/redact` actionable-error machinery for redaction trust-boundary
  failures so what/why/where/when/meaning/fix remain visible.

### Kickstart selection is the user-visible project/session boundary

- Kickstart persists `config.SelectionConfig`: `mode` (`all` or `selected`), per-harness project entries
  (`gitRemote`/`name`, optional branches), and explicit session IDs. `ingest.SelectionMatcher` is the
  canonical matcher already used by ingest, push, and prune; do not reimplement its semantics in React.
- **Required UI invariant (tracked in peasant#164; not yet landed):** when mode is `selected`, user-facing
  project and session LISTS show only the configured selection. This includes the WS/REST sessions lists,
  Home + Map project pickers, command palette, and share chooser. Explicit session selection must not
  widen visibility to every sibling session in its project. Mode `all` retains all-data behavior.
- Apply the boundary server-side so every consumer agrees, and derive counts/empty states from the same
  visible set. This is a visibility rule, NOT authorization to delete unselected historical rows. Preserve
  deep-link behavior until its policy is explicitly ratified.

### Git history and recorded sessions

- `session_commits` is the stored association between recorded sessions and Git commits. The current
  review-list wire collapses that richer relationship into `CommitRef.hasSession bool`; that boolean is
  insufficient for a user-facing work history because it cannot name or link the sessions.
- **Target experience (peasant#162):** Git is the timeline spine, annotated with the list of user sessions
  wherever associations are available. Bound vs candidate/temporal associations must not be conflated;
  unattached sessions remain discoverable. A wire change needs its own schema PR + tag before Peasant
  re-pins. The current `changes` label and `/review` routes remain in force until UAT ratifies a replacement;
  do not silently rename or delete them.

### Mounted UX contracts and known follow-ups

- **`/share` is canonical and shipped.** The persistent top-nav `share` action routes to `/share` and
  stays OUTSIDE Fairtrade's graph-section registry. Do not introduce `/push` as an alternate UI route.
  The graph registry remains `analytics | changes | code map`.
- The current share bridge auto-scans uncached selections; caches success AND honest failure by
  `(level, session)` across navigation; supports explicit re-scan; disables continuation on ANY failed
  session; and fails closed on category inconsistency. Preserve these semantics when replacing its UI.
- Fairtrade owns the future official review/redaction/consent/share composition
  (fairtrade-design-system#3). Fairtrade `RedactionReview` must gain a per-category filtered view while
  preserving controlled keep/revert state (fairtrade-design-system#4; prior art peasant#32). Peasant owns
  `/share`, scan/cache/auth/network orchestration, and Village-specific transport.
- The current code map is a known comprehension failure (peasant#165). Future work needs progressive,
  task-oriented disclosure and real-project UAT; do not merely add text around the same dense graph or
  fork Fairtrade's canonical graph visuals inside Peasant.
- In the mounted transcript viewer, the view toolbar, the sentence beginning "showing every step", and
  the steps overview must scroll away with the transcript (peasant#163). Do not leave them as a permanent
  `shrink-0` block outside the viewer scroll, and do not hardcode a 64px shell height where mobile uses the
  two-row header.
- **Current session-UX tracker:** peasant#166 links #162–#165 plus Fairtrade #3/#4. Treat the linked issue
  bodies as the validation/design records; this guide captures only ratified invariants and known gaps.

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
  runbook §6 checklist. The schema repo's runbook now carries its own §6 public-flip checklist
  mirroring peasant's; the approval-gate re-enable stays deferred to the flip in both, and its
  cross-repo unification is still an open followup.
- **Post-swap contract ceremony (IN EFFECT since the rc3 swap landed 2026-07-07):** a contract change is
  its own schema-repo PR + tag BEFORE the consumer PRs that re-pin it — stated in both peasant + village
  AGENTS.md checklists.
- **Shipped-artifact hygiene — WORKER-PREVENTED, reviewer-backstopped:** NO internal task taxonomy — `plabs-*` Beads IDs, `SLICE-N` / `W*-*` slice names, `LIP-N`, leaf-task IDs, or phase/epic codenames (`Wave 1`/`Wave-2`, `defer-2`, `PROPOSAL-N`) — in shipped **code, comments, docs/READMEs, OR commit messages**. Describe everything by substance (what the code does / why). **Prevention is the WORKER's job, not the reviewers':** never write internal tracking terminology into shipped artifacts in the first place, and **before reporting a slice complete, self-grep your changed files and scrub any hit** — e.g. `git diff --name-only <base>..HEAD | xargs grep -nE 'plabs-|SLICE-|W[0-9]+-|\bLIP-|Wave[ -]?[0-9]|defer-[0-9]|PROPOSAL-|\bTB\b'`. This is a mandatory pre-report gate so reviewers never spend cycles on expensive hygiene audits. The reviewer grep + the clean landing-squash message remain only as a **backstop**, not the primary catch. (`.tb-*` CSS selectors are real DOM names, not the taxonomy token — don't flag them. Pre-existing leaks from prior repo development are out of scope unless the user asks to clean them.)
- **Test cases live in FIXTURES, never inline — an ALL-AGENTS default, owned at every phase.** Combinatorial / table-driven / permutation test cases go in `testdata/*.yaml` fixtures (the typed-struct-with-`yaml:`-tags + `//go:embed testdata/<domain>/<name>.yaml` + `yaml.Unmarshal` + `Load…Fixtures()` idiom, with row-count guards), NOT inline case tables in `_test.go`. Cross-repo, not schema-specific: the schema module's `testdata/{grammar,workflow,publish,annotations,sync,quality,session-detail}` families AND peasant's e2e / `internal/testutil` `fixtures.yaml` patterns. A single schema change should update ONE YAML file, not N inline tables. **Every role owns this, not just the worker:** the **architect** designs the test strategy + validation cases around fixtures in the PROPOSAL (fixtures are the plan, inline is a design smell to call out); the **supervisor** bakes fixtures into the slice decomposition, the worker handoffs, and the review bar; the **worker** implements cases as fixtures by default (never inline-then-wait-for-review); the **reviewers** enforce it (any inline case table is a finding on every slice — test-quality especially, but all three flag it). Mutation-proving a test's non-vacuity is necessary but NOT sufficient — the cases must also be fixture-based. (Recurred repeatedly; codified 2026-07-11 after the user flagged it as a constant compliance gap — the user must never be the backstop for this.)
- **Do not delete real prior-version functionality just because the persistent chrome changed.** If a route or component still serves a real user flow, default to soft-retaining it as a deprecation candidate and keep every production evidence exit that depends on it working. Only delete genuinely dead scaffolding, never-shipped experiments, or orphan wiring. If it is unclear whether something is real user-facing functionality, surface the decision before removing it.
- **Production exits must be tested on the mounted production path.** Tests against dormant legacy components are not enough. If a retained route exists because a current surface links to it, test the current mounted surface action and assert the actual navigation or callback users trigger.
- **Shared shell visual gates compare canonical demo to current app.** For fairtrade adoption SxS artifacts, the left/reference side should be a screenshot of the fairtrade in-use demo and the right side should be the current consuming app. Do not compare app-generated baselines to the app unless that is explicitly the regression target.
- **"Shell" means chrome plus mounted body, not a nav strip.** A shell screenshot must include persistent product header, section navigation, active-section state, route/view wiring, and representative body content for the mounted surface. Gates should fail closed when either side is missing or blank so they cannot pass on chrome-only captures.
- **Graph app section order is canonical:** `analytics | changes | code map` (user-updated 2026-07-01, superseding the earlier `analytics | code map | changes`). Fairtrade owns the shared section registry (`GRAPH_APP_SECTIONS` in `src/ui/inuse/InUseShell.jsx`); consumers derive from it and fail loudly on unknown or unmapped section IDs rather than silently dropping sections. The session-annotated-timeline follow-up (peasant#162) may propose a different label/IA, but the existing order and IDs remain binding until that change is user-ratified and lands in Fairtrade first.

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
- **Model routing (user override, 2026-07-15):** use `gpt-5.6-luna` for scouting and implementation
  workers, `gpt-5.6-terra` for mid-implementation review, and `gpt-5.6-sol` for final implementation
  review, unless the user gives a task-specific override (for example, the share-nav fix explicitly used
  Terra at high effort for implementation). Planning/architecture uses the highest available tier unless
  the user specifies one. If the runtime cannot select the requested model, surface that limitation; do
  not silently substitute and claim the requested model ran.
- **Review context is STANDING even when the stage model changes** (A = Correctness, B = Test-quality,
  C = Elegance): preserve grounding, prior findings, and the full regression checklist across plan and
  code review waves; re-task persistent teammates where the runtime supports it, or hand the full context
  to the stage-appropriate reviewer. **Keep reviewers pre-reading relevant slices + grounding
  (URD/handoff/scratchpad/source) BETWEEN waves so they are warm before review fires.** Plan review needs
  all three to ACCEPT; code review needs a clean 0/0/0 fix-free round before the gate clears.
- **Proposal numbering is per-epoch:** each epoch restarts at PROPOSAL-1 (and SLICE-1, etc.) — do NOT continue a prior epoch's global sequence. Revisions increment within the epoch (PROPOSAL-1 → PROPOSAL-2 …).
- **Review completed slices in ONE wave, not piecemeal.** When multiple slices finish, dispatch the standing reviewers over ALL currently-completed slices in a single coordinated review wave — accumulate the done batch rather than firing a separate review round as each slice trickles in. Per-slice verdicts + severity trees are still preserved (one wave ≠ one merged severity tree across slices); the "wave" is about batching the *dispatch/timing*, not collapsing per-slice granularity.

## Current state (2026-07-17)
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
- **Schema consumers remain on `v0.1.0-rc5`; the module's latest tag is `v0.1.0-rc6`.** Schema rc4 added
  the pull content/annotation skip-gate contract; rc5 corrected the canonical git-remote redaction fixture
  without changing the OpenAPI wire. Peasant#146 and village#38 are landed on the rc5 pin.
- **Schema TypeScript contract package: LANDED + RELEASED 2026-07-17** (schema#29, PR #30 squash-merged as
  `64716f6`; release PR #31 → tag `v0.1.0-rc6`, GitHub prerelease). The bespoke Go→TS emitter is replaced
  by Hey API + Zod (root) and `openapi-typescript` (type-only Local/Village operation contracts), with
  fixture-backed export-identity/mutation/tarball/freshness gates, `$ref`-anchored nominal `ProjectHash`,
  and Go-generated closed sets. rc6 also carries Village API `0.6.0`, Local API `0.4.0` with typed map
  diff enums (`FileChangeStatus`, `DiffLineKind`), and Types `0.3.0`.
- **`@peasant-labs/schema@0.1.0-rc6` PUBLISHED on npm 2026-07-17** (public, dist-tag `next`; maintainer-run
  first publish from the verified tag checkout). Ceremony automation via OIDC trusted publishing +
  `npm-publish` environment is landing as schema#32; consumer re-pins + the transcript-consumer TS
  migration (deprecated shim) remain the open follow-ups.
- **Git-context redaction + hardened share bridge: LANDED 2026-07-15 (peasant#146).** Git remote URLs and
  branch output stay semantic `CategoryProject` but fire only at Maximum via `Rule.MinimumLevel`;
  `CategoryString` is the public canonical renderer; unknown categories and scan failures fail closed.
  `/share` is linked from the persistent nav and remains separate from the graph section registry.
- **Current Peasant session UX gaps are tracked in peasant#166:** configured-list scope (#164), a
  session-annotated Git timeline (#162), transcript header scrolling (#163), code-map legibility (#165),
  and the Fairtrade share/redaction component follow-ups (#3/#4).
- Other open follow-ups: the fairtrade rollout followup epic, transcript-browser#5 (scorecard richness),
  peasant#143 (git cluster on the wire), and the licensing ledgers peasant#151 ⇄ village#29.
  (The schema repo's `internal/contractgates/doc.go` taxonomy leak was already scrubbed 2026-07-07;
  a broader scrub of the remaining public-godoc comments is in progress.) (Beads IDs in `.agents.local/`.)

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
