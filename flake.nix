{
  description = "Reproducible Go dev environment with build and test support";

  # ============================================================
  # INPUTS
  # ============================================================

  inputs = rec {
    nixpkgs-stable.url = "github:NixOS/nixpkgs/nixos-26.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixpkgs = nixpkgs-unstable;
    flake-utils.url = "github:numtide/flake-utils";
  };

  # ============================================================
  # OUTPUTS
  # ============================================================

  outputs =
    inputs@{ self
    , nixpkgs
    , nixpkgs-stable
    , nixpkgs-unstable
    , flake-utils
    , ...
    }:
    let
      # ==========================================================
      # PROJECT CONFIGURATION — edit this section for your project
      # ==========================================================

      # Package metadata
      pname = "peasant-labs";

      # Version is derived from the git short rev: this is a -dev/source build,
      # NOT a tagged release. self.shortRev exists only for a clean tree; fall
      # back to dirtyShortRev, then a literal, so `nix build` works on a dirty
      # working tree too. The schema module ships no version-injection var, so
      # this is NOT injected via ldflags (unlike peasant's internal/defaults).
      version = self.shortRev or self.dirtyShortRev or "dev";

      # Go package attribute (e.g., go, go_1_26)
      # Set to null to use the default Go version from nixpkgs
      goAttr = "go_1_26";

      # Vendor hash for buildGoModule. It covers ONLY the third-party deps in
      # go.sum, so a FIRST-PARTY edit (e.g. a schema testdata YAML) never drifts
      # it — the #119 pathology required peasant's local `replace` and is absent
      # in this leaf module (proven by TestVendorHashStableOnFirstPartyEdit).
      # Recompute ONLY on a go.mod/go.sum dep bump: set this to
      # nixpkgs.lib.fakeHash, run `nix build`, copy the reported `got:` hash here.
      vendorHash = null;

      # Extra CLI tools available in the dev shell. The contract-gate CLIs
      # (oasdiff / go-apidiff / vacuum) are dev/CI tools and MUST NOT enter
      # go.mod (the leaf-audit test enforces the require set). They are
      # provisioned here so `nix develop` (and CI, which runs through the same
      # flake) is the single dev-dependency manifest:
      #   - vacuum  : Go-native OpenAPI linter, packaged in nixpkgs as vacuum-go
      #               (binary name `vacuum`).
      #   - oasdiff : OpenAPI breaking-change diff — NOT in nixpkgs, so built
      #               from source by the `oasdiff` buildGoModule derivation in the
      #               inner let below and appended to the dev shell there.
      #   - go-apidiff : exported-Go-API breaking-change diff — likewise built
      #               from source by the `go-apidiff` derivation below.
      # The two source-built gates can't be named here (they need `pkgs`, which is
      # only bound inside mkOutputs); they are appended to devShell.packages.
      devTools = pkgs: with pkgs; [
        go_1_26
        gopls # LSP
        gotools # goimports, godoc, etc.
        go-tools # staticcheck
        delve # debugger
        ast-grep # structural code search and lint
        golangci-lint # linter suite
        actionlint # lint GitHub Actions workflow YAML (.github/workflows/*.yml)
        vacuum-go # Go-native OpenAPI/Swagger linter (contract gate; binary: vacuum)
        pnpm
        typescript
        typescript-language-server
      ];

      # Native build dependencies (C libraries, system packages). The schema leaf
      # is pure Go (modernc/zombiezen sqlite are cgo-free), so none are required.
      nativeBuildDeps = pkgs: with pkgs; [
      ];

      # Extra check commands run during `nix build` after go test
      extraCheckPhase = ''
        # go vet ./...
        # staticcheck ./...
      '';

      # Files to install alongside the binary (relative to src)
      extraInstallPhase = ''
        # mkdir -p $out/share/policies
        # cp authz/policies/*.rego $out/share/policies/
      '';

      # ==========================================================
      # IMPLEMENTATION — you shouldn't need to edit below here
      # ==========================================================

      mkOutputs = nixpkgs-channel:
        flake-utils.lib.eachDefaultSystem (system:
          let
            pkgs = import nixpkgs-channel {
              inherit system;
              config.allowUnfree = true;
            };

            goPackage =
              if goAttr != null
              then pkgs.${goAttr}
              else pkgs.go;

            # ----------------------------------------------------------
            # Contract-gate CLIs built from source (not in nixpkgs)
            # ----------------------------------------------------------
            # These are dev/CI tools, NEVER go.mod requires (the leaf-audit test
            # enforces that). They are appended to devShell.packages and also
            # exposed as packages.{oasdiff,go-apidiff} so CI can `nix build`
            # them and the synthetic-break tests find them on PATH inside
            # `nix develop`. vendorHash covers each tool's OWN third-party graph;
            # recompute (set to lib.fakeHash, `nix build .#<tool>`, copy `got:`)
            # only on a version bump.

            # oasdiff — OpenAPI breaking-change diff. https://github.com/oasdiff/oasdiff
            oasdiff = pkgs.buildGoModule {
              pname = "oasdiff";
              version = "1.19.1";
              src = pkgs.fetchFromGitHub {
                owner = "oasdiff";
                repo = "oasdiff";
                rev = "v1.19.1";
                hash = "sha256-fAMeFt3bmkxTXZuhGIlazga4lGnTCNIlXEST3NGnjFI=";
              };
              vendorHash = "sha256-+bRE23X6KL2Y7hdXPRxPu3WFPMWrjipINyf+5lJn0Q0=";
              # The CLI main is at the module root; don't build/test the library
              # subpackages (faster, and avoids any network-touching tests).
              subPackages = [ "." ];
              doCheck = false;
              env.CGO_ENABLED = 0;
              ldflags = [ "-s" "-w" ];
              meta = with pkgs.lib; {
                description = "OpenAPI diff and breaking-change detector (contract gate)";
                homepage = "https://github.com/oasdiff/oasdiff";
                license = licenses.asl20;
                mainProgram = "oasdiff";
              };
            };

            # go-apidiff — exported-Go-API breaking-change diff over two git refs.
            # https://github.com/joelanford/go-apidiff
            go-apidiff = pkgs.buildGoModule {
              pname = "go-apidiff";
              version = "0.8.3";
              src = pkgs.fetchFromGitHub {
                owner = "joelanford";
                repo = "go-apidiff";
                rev = "v0.8.3";
                hash = "sha256-qDx+vGmXFdFTMXHT6/5mbsGagvBixsxUkXmNg6dI/SE=";
              };
              vendorHash = "sha256-TEesxbzvlT9VeVujbPzfd6fSQZJMzf/9KoiWECrY7wk=";
              doCheck = false;
              env.CGO_ENABLED = 0;
              ldflags = [ "-s" "-w" ];
              meta = with pkgs.lib; {
                description = "Detect incompatible changes in a Go module's exported API across git refs (contract gate)";
                homepage = "https://github.com/joelanford/go-apidiff";
                license = licenses.asl20;
                mainProgram = "go-apidiff";
              };
            };

            contractGateTools = [ oasdiff go-apidiff ];

            # ----------------------------------------------------------
            # Build
            # ----------------------------------------------------------

            #package = null;

            #pkgs.buildGoModule {
            #  inherit pname version;
            #  src = ./.;
            #  inherit vendorHash;

            #  # Build the schema repo's dev/CI tools. cmd/schema-gen regenerates
            #  # the OpenAPI specs + Redoc HTML; cmd/release-guard is the release
            #  # pipeline's title/tag/guard CLI. The schema module ships NO runtime
            #  # binary (it is a contract-only leaf). The default `./...` would also
            #  # try to "build" the library packages, which is fine, but we name the
            #  # two commands explicitly so the package output is just those tools.
            #  subPackages = [ "cmd/schema-gen" "cmd/release-guard" ];

            #  # Pure-Go leaf (no cgo deps) → CGO disabled for a static, portable
            #  # tool binary.
            #  env.CGO_ENABLED = 0;

            #  # Strip debug info for smaller binaries. No -X version injection: the
            #  # schema module has no internal/defaults.version var (W8).
            #  ldflags = [
            #    "-s"
            #    "-w"
            #  ];

            #  nativeBuildInputs = nativeBuildDeps pkgs;

            #  # The schema leaf is pure Go and fully hermetic (no git/network in
            #  # tests), so the whole suite runs as a packaging sanity gate. No
            #  # -race: the detector requires cgo and this build is CGO_ENABLED=0;
            #  # the authoritative race-enabled suite runs in CI (`go test -race`).
            #  checkPhase = ''
            #    runHook preCheck
            #    go test ./...
            #    ${extraCheckPhase}
            #    runHook postCheck
            #  '';

            #  postInstall = extraInstallPhase;

            #  meta = with pkgs.lib; {
            #    description = "Peasant public API contract: OpenAPI specs, shared types, fixtures, validators, and migrations (single leaf module)";
            #    homepage = "https://github.com/peasant-labs/schema";
            #    # PLACEHOLDER license: this public contract repo has no committed
            #    # LICENSE yet. Do NOT claim a stock SPDX id (that would be a lie to
            #    # nixpkgs/validators). The final license is a user decision (see
            #    # README open items); config.allowUnfree = true keeps `nix build`
            #    # unblocked until then. Revisit when LICENSE is committed.
            #    license = {
            #      shortName = "LicenseRef-Peasant-Schema-Placeholder";
            #      fullName = "Peasant Schema License (placeholder; final license TBD — no LICENSE committed yet)";
            #      free = false;
            #    };
            #    mainProgram = "schema-gen";
            #  };
            #};

            # ----------------------------------------------------------
            # Development Shell
            # ----------------------------------------------------------

            devShell = pkgs.mkShell {
              name = "${pname}-dev";
              #inputsFrom = [ ];
              # devTools (incl. vacuum-go from nixpkgs) + the source-built
              # oasdiff/go-apidiff gates, so `nix develop` and CI share one
              # contract-gate toolchain.
              packages = (devTools pkgs) ++ contractGateTools;

              shellHook = ''
                echo "Go $(go version | cut -d' ' -f3) dev shell"
                export CGO_ENABLED=1
                [ -f .envrc.local ] && source .envrc.local || true
              '';
            };

          in
          {
            # Contract-gate CLIs, exposed so CI can `nix build .#oasdiff` /
            # `.#go-apidiff` and the dev shell provisions them.
            packages.oasdiff = oasdiff;
            packages.go-apidiff = go-apidiff;

            devShells.default = devShell;

            # Quick check: nix flake check
            #checks.build = package;
          }
        );
    in
    mkOutputs nixpkgs;
}
