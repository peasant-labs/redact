# redact

`github.com/peasant-labs/redact` is the redaction engine: a Go module, no
application. `make check` is the gate (`fmt`, `vet`, `test`, then the static
guard). The module requires `github.com/peasant-labs/schema` at the version in
`go.mod`.

## Static guard

`make check-unstring` runs `unstring` v0.0.4 over this module. It needs Go 1.26+
and ast-grep 0.51.2 on `PATH`. This repository has no flake, so a contributor
outside the workspace dev shell installs that pin with `npm install --global @ast-grep/cli@0.51.2`.
`make check` runs that same command and stops when the guard fails.

`.unstring-baseline.yaml` is generated. Do not edit it. `make unstring-update`
lowers it. `.unstring.yaml` sets `schema.module` to
`github.com/peasant-labs/schema`, so the catalog is this tree plus the closed
sets in the pinned schema module.

A deliberate exception is `// unstring-allow: <rule-id> — <reason>` with at
least three words after the em dash. `closed-set-literal` and
`go-closed-set-literal` accept no marker. A generated-code exemption goes in
`.unstring.yaml`; for those two rules, and for `rule: "*"`, every matched file
must carry a `Code generated … DO NOT EDIT` header.

The tool contract is
[infra/unstring/README.md](https://github.com/peasant-labs/infra/blob/unstring/v0.0.4/unstring/README.md).
