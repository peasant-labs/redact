package redact

import "regexp"

var gitRemoteSSHPattern = regexp.MustCompile(`git@(?:github\.com|gitlab\.com|bitbucket\.org):[a-zA-Z0-9_.-]+/[^\s"'\\]+`)

// init appends the 10 CategoryProject rules to the shared Rules table. Most use
// the category's Standard minimum; git remotes and branch output explicitly
// require Maximum.
//
// Rule design rationale:
//   - Patterns are anchored tightly enough to avoid documentation false positives
//     while still covering all common forms of each construct.
//   - git_remote_https / git_remote_ssh: limited to the three major public hosters.
//     Self-hosted instances can use a user-configured project pattern, which
//     inherits the project category's Standard minimum.
//   - go_import_path / go_module_path: require at least org/repo (two path segments)
//     so bare "github.com" mentions in prose do not trigger.
//   - docker_image_ref: requires a slash (org/repo or registry/org/repo); single-word
//     image names like "ubuntu" or "postgres" are not matched to avoid over-redaction.
//   - git_branch_output: matches "* branch/name" (git branch -a local) or
//     "origin/branch/name" (remote tracking refs) — requires at least one
//     slash so single-word branch names in prose do not trigger.
//   - gitlab_ci_project / github_actions_repo: anchor on the known variable name prefix
//     so any value on the right-hand side is captured without false positives.
func init() {
	Rules = append(Rules, projectRules...)
}

// projectRules is the ordered list of 10 CategoryProject rules.
// Defined as a package-level var so tests can reference individual rules by index,
// and so init() can append them to Rules in a single allocation.
var projectRules = []Rule{
	{
		// git_remote_https matches HTTPS remote URLs for GitHub, GitLab, and Bitbucket.
		//
		// Pattern: https?:// followed by one of the three hostnames, a path with
		// at least one slash (org/repo), and no whitespace or quotes.
		//
		// Boundary: the URL ends at the first whitespace, quote, or backslash so
		// multi-word sentences containing a URL do not consume surrounding text.
		ID:           "git_remote_https",
		Category:     CategoryProject,
		MinimumLevel: Maximum,
		Pattern:      regexp.MustCompile(`https?://(?:github\.com|gitlab\.com|bitbucket\.org)/[^\s"'\\]+`),
		Replacement:  "<PROJECT_URL>",
	},
	{
		// git_remote_ssh matches SSH remote URLs for the same three hosters.
		//
		// Pattern: git@ followed by hostname:org/repo style path.
		// The colon separates the host from the path (SCP syntax).
		ID:           "git_remote_ssh",
		Category:     CategoryProject,
		MinimumLevel: Maximum,
		Pattern:      gitRemoteSSHPattern,
		Replacement:  "<PROJECT_URL>",
	},
	{
		// go_import_path matches quoted Go import paths rooted at github.com.
		//
		// Pattern: a double-quoted string starting with github.com/ followed by
		// at least org/repo (two non-empty path segments). Additional sub-packages
		// are matched by the trailing optional group.
		//
		// The surrounding quotes are included in the match and preserved in the
		// replacement so the surrounding Go source syntax remains syntactically valid.
		ID:          "go_import_path",
		Category:    CategoryProject,
		Pattern:     regexp.MustCompile(`"github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*"`),
		Replacement: `"<GO_IMPORT>"`,
	},
	{
		// go_module_path matches module declarations in go.mod files.
		//
		// Pattern: the keyword "module" followed by whitespace and a github.com path
		// with at least org/repo (two non-empty segments).
		//
		// The "module" keyword is preserved in the replacement so go.mod files
		// remain syntactically valid after redaction.
		ID:          "go_module_path",
		Category:    CategoryProject,
		Pattern:     regexp.MustCompile(`module\s+github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+`),
		Replacement: "module <GO_MODULE>",
	},
	{
		// npm_repo_url matches repository/homepage/bugs fields in package.json.
		//
		// Pattern: one of the three JSON field names, followed by a colon, optional
		// whitespace, and an HTTPS GitHub URL. The opening quote of the value is
		// included to anchor the pattern within JSON context.
		ID:          "npm_repo_url",
		Category:    CategoryProject,
		Pattern:     regexp.MustCompile(`"(?:repository|homepage|bugs)":\s*"https?://github\.com/[^"]+`),
		Replacement: "<NPM_REPO>",
	},
	{
		// docker_image_ref matches Docker image references with a slash separator.
		//
		// Pattern: the keywords FROM or "image:" followed by whitespace and an image
		// reference of the form org/repo or registry/org/repo, with an optional tag.
		//
		// Requiring a slash prevents single-word official images ("ubuntu", "postgres")
		// from triggering — those are public names that do not expose project identity.
		// The tag portion (:tag) is optional and must consist of alphanum + dots + dashes.
		ID:          "docker_image_ref",
		Category:    CategoryProject,
		Pattern:     regexp.MustCompile(`(?:FROM|image:)\s+[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?::[a-zA-Z0-9_.-]+)?`),
		Replacement: "<DOCKER_IMAGE>",
	},
	{
		// ghcr_image_ref matches GitHub Container Registry image references.
		//
		// Pattern: ghcr.io/ followed by org/image, with an optional tag or digest.
		// The ghcr.io hostname is a strong anchor — no ambiguity with prose text.
		ID:          "ghcr_image_ref",
		Category:    CategoryProject,
		Pattern:     regexp.MustCompile(`ghcr\.io/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?::[a-zA-Z0-9_.-]+)?`),
		Replacement: "<GHCR_IMAGE>",
	},
	{
		// git_branch_output matches branch references that appear in git command output.
		//
		// Two forms are matched:
		//   "* org/branch"  — current branch in `git branch -a` output
		//   "origin/branch" — remote tracking ref
		//
		// Requiring at least one slash (org/branch or remote/branch) prevents matching
		// single-word branch names like "main" or "develop" in prose text. Feature branches
		// named "org/feature" or remote tracking refs "origin/feature" are the target.
		ID:           "git_branch_output",
		Category:     CategoryProject,
		MinimumLevel: Maximum,
		Pattern:      regexp.MustCompile(`(?:\*\s+|origin/)[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+`),
		Replacement:  "<BRANCH>",
	},
	{
		// gitlab_ci_project matches GitLab CI environment variables that expose project identity.
		//
		// Variables covered: CI_PROJECT_NAME, CI_PROJECT_PATH, CI_PROJECT_URL.
		// Pattern: variable name followed by = or : (shell assignment or YAML key)
		// and the value (any non-whitespace sequence).
		ID:          "gitlab_ci_project",
		Category:    CategoryProject,
		Pattern:     regexp.MustCompile(`CI_PROJECT_(?:NAME|PATH|URL)\s*[=:]\s*\S+`),
		Replacement: "<CI_PROJECT>",
	},
	{
		// github_actions_repo matches the GITHUB_REPOSITORY environment variable.
		//
		// Pattern: the variable name followed by = or : and the value (owner/repo form).
		// GITHUB_REPOSITORY is always set by GitHub Actions and always contains the
		// owner/repo identity of the repository running the workflow.
		ID:          "github_actions_repo",
		Category:    CategoryProject,
		Pattern:     regexp.MustCompile(`GITHUB_REPOSITORY\s*[=:]\s*\S+`),
		Replacement: "<GH_REPO>",
	},
}
