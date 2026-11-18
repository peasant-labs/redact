package redact

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Rules that find a credential by the construct around it: an Authorization
// header with a scheme other than Bearer or Basic, the user option of a curl
// command, and the private members of a JSON Web Key.

const (
	authorizationTokenRuleID = "authorization_token"
	curlUserPasswordRuleID   = "curl_user_password"
	jwkPrivateMemberRuleID   = "jwk_private_member"

	jwkPrivateMemberPlaceholder = "<JWK_PRIVATE_KEY>"
)

// authorizationTokenPattern matches an Authorization header whose scheme is
// "token" or "Bot". bearer_token and basic_auth cover the other two schemes.
//
//   - "token": https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api
//     ("you can use Authorization: Bearer or Authorization: token to pass a token")
//   - "Bot":   https://docs.discord.com/developers/reference#authentication
//     ("Authorization: Bot <token>")
//
// The header name and the scheme stay in the output. The value uses the
// character set and the 20-character floor of bearer_token, so a placeholder
// such as YOUR-TOKEN or a variable reference does not match.
var authorizationTokenPattern = regexp.MustCompile(
	`(?i)(authorization(?:\\*["'])?:[ \t]*(?:\\*["'])?(?:token|bot)[ \t]+)[a-z0-9_\-.+/=]{20,}`)

// curlUserPasswordPattern matches the user option of a command line and takes
// the password after the first colon:
//
//	-u, --user <user:password>
//	https://curl.se/docs/manpage.html#-u
//	("The username and passwords are split up on the first colon")
//
// The option alone is not enough, because other commands use -u for other
// things (sort -u, git push -u). curlUserPasswordFilter keeps a match only when
// the command on that line is curl. The match starts at the option and not at
// the command, so it does not cover, and cannot displace, a match of another
// rule earlier on the line.
//
// The user name and the password do not start with $, < or {, so a variable
// reference and a template are not matched. A user name with no colon after
// it makes curl ask for the password, and holds none.
var curlUserPasswordPattern = regexp.MustCompile(
	`((?:^|[ \t])(?:-u|--user)(?:[ \t]+|=)(?:\\*["'])?[^\s:"'$<{\\]+:)([^\s"'$<{\\][^\s"'\\]*)`)

// curlCommandPattern is the command word itself, not a longer word around it.
var curlCommandPattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.\-])curl(?:\.exe)?(?:[ \t]|\\|$)`)

// placeholderPasswords are the words documentation writes in place of a
// password: curl -u user:password.
var placeholderPasswords = []string{"password", "passwd", "pass", "pwd", "secret", "token", "key", "apikey", "api_key"}

// maxCommandLookback bounds how far back curlUserPasswordFilter looks for the
// command word.
const maxCommandLookback = 4096

// curlUserPasswordFilter keeps a match whose option belongs to a curl command
// and whose password is not a documentation placeholder.
func curlUserPasswordFilter(matched, input string, offset int) bool {
	groups := curlUserPasswordPattern.FindStringSubmatchIndex(matched)
	if groups == nil || groups[0] != 0 {
		return false
	}
	if slices.Contains(placeholderPasswords, strings.ToLower(matched[groups[4]:groups[5]])) {
		return false
	}
	return curlCommandPattern.MatchString(commandBefore(input, offset))
}

// commandBefore returns the text of the command that position offset belongs
// to: the start of its line up to offset, after the last operator that starts
// another command. A line that the line before it continues with a trailing
// backslash is part of the same command.
func commandBefore(input string, offset int) string {
	floor := max(0, offset-maxCommandLookback)
	start := offset
	for start > floor {
		lineStart := strings.LastIndexByte(input[floor:start], '\n')
		if lineStart < 0 {
			start = floor
			break
		}
		lineStart += floor
		before := strings.TrimRight(input[floor:lineStart], " \t\r")
		if !strings.HasSuffix(before, `\`) {
			start = lineStart + 1
			break
		}
		start = lineStart
	}
	command := input[start:offset]
	// A pipe, a semicolon or && with a space beside it starts another command.
	// An operator character with no space beside it is left alone: it is part
	// of a quoted URL far more often than it is an operator.
	for _, operator := range commandOperators {
		if cut := strings.LastIndex(command, operator); cut >= 0 {
			command = command[cut+len(operator):]
		}
	}
	return command
}

// commandOperators separate two commands on one line.
var commandOperators = []string{" | ", "; ", " && ", " || "}

// jwkPrivateMembers is the closed list of JSON Web Key members that hold
// private or secret key material:
//
//	d                 RSA private exponent, EC and OKP private key
//	p, q, dp, dq, qi  RSA primes and CRT values (the key follows from them)
//	k                 the key of a symmetric ("oct") key
//
// RFC 7518 sections 6.2.2, 6.3.2 and 6.4.1; RFC 8037 section 2.
var jwkPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k"}

// jwkKeyTypeMember is the member every JSON Web Key carries (RFC 7517
// section 4.1). It is what tells a key from any other object with a "d".
const jwkKeyTypeMember = "kty"

// jwkContextWindow is how far from a private member the key-type member may
// be. A 4096-bit RSA key in JWK form is about 3.2 KiB.
const jwkContextWindow = 4096

// minJWKMemberLength is a noise floor, not a format fact: 16 bytes, the
// smallest key in use, are 22 base64url characters.
const minJWKMemberLength = 22

// jwkValueBody is a base64url value of at least minJWKMemberLength characters.
var jwkValueBody = `[A-Za-z0-9_\-]{` + strconv.Itoa(minJWKMemberLength) + `,}={0,2}`

// jwkPrivateMemberPattern matches a private member and its base64url value,
// with plain or escaped quotes. The member name stays in the output.
// jwkPrivateMemberFilter keeps a match only inside a JSON Web Key.
var jwkPrivateMemberPattern = regexp.MustCompile(
	`(\\*"(?:` + strings.Join(jwkPrivateMembers, "|") + `)\\*"[ \t]*:[ \t]*\\*")` + jwkValueBody)

// jwkValuePattern is a whole member value, for RedactJSON.
var jwkValuePattern = regexp.MustCompile(`^` + jwkValueBody + `$`)

// jwkKeyTypePattern is the key-type member with plain or escaped quotes.
var jwkKeyTypePattern = regexp.MustCompile(`\\*"` + jwkKeyTypeMember + `\\*"[ \t]*:`)

// jwkPrivateMemberFilter keeps a match that has a key-type member near it.
func jwkPrivateMemberFilter(matched, input string, offset int) bool {
	start := max(0, offset-jwkContextWindow)
	end := min(len(input), offset+len(matched)+jwkContextWindow)
	return jwkKeyTypePattern.MatchString(input[start:end])
}

// isJWKPrivateMember reports whether RedactJSON replaces the value of key in
// an object that carries a key-type member.
func isJWKPrivateMember(key, value string) bool {
	return slices.Contains(jwkPrivateMembers, key) && jwkValuePattern.MatchString(value)
}
