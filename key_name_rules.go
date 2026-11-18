package redact

import (
	"regexp"
	"strings"
	"unicode"
)

// Rules that find a secret by the name of the key that holds it, instead of by
// the shape of the value. A value with no known format is still a credential
// when it sits under a name such as DB_PASSWORD or session_token.
//
// The name test and the value test live here, in one place. The text rules
// (key_name_secret, url_query_secret) and RedactJSON all call them, so the three
// forms cannot disagree.

const (
	keyNameSecretRuleID  = "key_name_secret"
	urlQuerySecretRuleID = "url_query_secret"
	cookieHeaderRuleID   = "cookie_header"

	// keyNameSecretPlaceholder replaces the value. The name and the separator
	// stay in the output, so a reader still sees which setting was removed.
	keyNameSecretPlaceholder = "<SECRET>"
	cookieHeaderPlaceholder  = "<COOKIE>"
)

// Value thresholds. A name in credentialNameEndings names one credential
// value, and a password may be short and hold no digit, so its value is held
// to the lower pair. A name in keyMaterialNameEndings also names many values
// that are not credentials (a key identifier, an authentication mode), so its
// value is held to the higher pair and must mix letters and digits.
const (
	minCredentialValueLength  = 8
	minCredentialValueEntropy = 3.0
	minKeyMaterialValueLength = 20
	minKeyMaterialEntropy     = 3.5
)

// credentialNameEndings is the closed list of name endings, compared without
// case, that name one credential value: DB_PASSWORD, pgpasswd, clientSecret,
// GITHUB_TOKEN. A name that only contains the word does not end with it:
// PASSWORD_MIN_LENGTH, token_type, max_tokens.
var credentialNameEndings = []string{"token", "secret", "password", "passwd", "passphrase"}

// keyMaterialNameEndings is the closed list of name endings held to the strict
// value test. The underscore in an entry also stands for a hyphen or for no
// separator, so "api_key" covers api-key, apikey and apiKey.
//
// "auth" is here and not above because a name that ends in it usually holds a
// scheme, a mode or a nested object (auth: basic, auth: required). Only a long
// value that mixes letters and digits, such as the encoded pair a registry
// configuration stores under "auth", is taken.
var keyMaterialNameEndings = []string{"credential", "private_key", "access_key", "api_key", "secret_key", "auth"}

// secretNamePattern is a name that ends in one of the two lists. It is built
// from the lists, so the patterns and secretNameKind read one definition.
var secretNamePattern = func() string {
	endings := make([]string, 0, len(credentialNameEndings)+len(keyMaterialNameEndings))
	for _, ending := range credentialNameEndings {
		endings = append(endings, regexp.QuoteMeta(ending))
	}
	for _, ending := range keyMaterialNameEndings {
		endings = append(endings, strings.ReplaceAll(regexp.QuoteMeta(ending), "_", "[_-]?"))
	}
	return `[a-z0-9_.\-]*(?:` + strings.Join(endings, "|") + `)`
}()

// keyNameSecretPattern matches a secret name, a separator and a value on one
// line. It uses no lookaround and no backreference.
//
// Group 1 is everything before the value: the name, an optional closing quote
// of the name, and the separator. The forms are
//
//	NAME=value   NAME: value   NAME := value   "name": "value"   --name value
//
// The value is one of four alternatives, and each keeps its own quotes outside
// the value group so the replacement can put them back:
//
//	groups 2-4   "value"    a double-quoted string, escapes allowed inside
//	groups 5-7   \"value\"  the same member inside a JSON string, quotes escaped
//	groups 8-10  'value'    a single-quoted string
//	group 11     value      unquoted, up to the next space
//
// A quoted value holds no space: a quoted text with spaces is a description,
// and the pattern does not match it. An unquoted value does not start with =,
// < or > (so ==, => and <template> are not values), stops before < and >, and
// does not end in the punctuation that closes a call or a list.
var keyNameSecretPattern = regexp.MustCompile(
	`(?i)(--` + secretNamePattern + `[ \t]+|` + secretNamePattern + `(?:\\*["'])?[ \t]*(?::=|[=:])[ \t]*)` +
		`(?:(")((?:[^"\s\\]|\\[^\s])+)(")` +
		`|(\\+")([^"\s\\]+)(\\+")` +
		`|(')([^'\s]+)(')` +
		"|([^\\s\"'`<>=\\\\](?:[^\\s\"'`<>]*[^\\s\"'`<>\\\\,;)\\]}])?))")

// keyNameSecretReplacement keeps group 1 and whichever pair of quotes matched.
const keyNameSecretReplacement = "${1}${2}${5}${8}" + keyNameSecretPlaceholder + "${4}${7}${10}"

// keyNameSecretValueGroups are the value groups of keyNameSecretPattern.
var keyNameSecretValueGroups = [...]int{3, 6, 9, 11}

// urlQuerySecretPattern matches a secret-named parameter in a URL query. The
// value stops at the next parameter or the fragment, which the general pattern
// cannot do without cutting a password that contains "&".
var urlQuerySecretPattern = regexp.MustCompile(
	"(?i)([?&]" + secretNamePattern + "=)([^\\s\"'`<>&#]+)")

// cookieHeaderPattern matches the value of a Cookie or Set-Cookie header, as a
// header line or as a JSON member. The value must start with a cookie name and
// an equals sign, so prose after the word "Cookie:" does not match, and the
// first cookie value must not open a template or a variable reference. The
// whole header value is replaced: every pair in it, and the attributes of a
// Set-Cookie header.
var cookieHeaderPattern = regexp.MustCompile(
	`(?i)\b((?:set-)?cookie(?:\\*["'])?:[ \t]*(?:\\*["'])?)[a-z0-9_.\-]+=[^\s;"'<${\\][^\r\n"'\\]*`)

// secretNameKind says which value test a secret name asks for.
type secretNameKind int

const (
	notSecretName secretNameKind = iota
	credentialName
	keyMaterialName
)

// secretNameKindOf classifies a name by its ending.
func secretNameKindOf(name string) secretNameKind {
	lower := strings.ToLower(name)
	for _, ending := range credentialNameEndings {
		if strings.HasSuffix(lower, ending) {
			return credentialName
		}
	}
	joined := strings.NewReplacer("_", "", "-", "").Replace(lower)
	for _, ending := range keyMaterialNameEndings {
		if strings.HasSuffix(joined, strings.ReplaceAll(ending, "_", "")) {
			return keyMaterialName
		}
	}
	return notSecretName
}

var (
	// wordValuePattern is a value of letters alone, with underscores or
	// hyphens between them: an identifier (hashedPassword, user_password), a
	// literal or type name (null, string), or a placeholder (your-api-key).
	wordValuePattern = regexp.MustCompile(`^[A-Za-z_\-]+$`)
	// dottedIdentifierPattern is a member access or an environment read:
	// process.env.TOKEN, request.body.token, var.database_password.
	dottedIdentifierPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$`)
	// indexedIdentifierPattern is an identifier that is then indexed:
	// os.environ[, ENV[, argv[.
	indexedIdentifierPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$.]*\[`)
	// versionValuePattern is a version or an image tag: 1.2.3, v0.24.1-rc1.
	versionValuePattern = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+)+(?:[-+._][A-Za-z0-9]+)*$`)
)

// notCredentialPrefixes open a value that is a reference, a template, a
// structure, a path or a block header instead of a credential:
//
//	$VAR ${VAR} $(cmd)   variable reference or command substitution
//	%s %(name)s          format verb
//	{name} {{ .Value }}  template or the start of an object
//	[REDACTED] [a, b]    marker or the start of a list
//	/etc/x ~/x ./x ../x  path to a file
//	-----BEGIN           a PEM block, which private_key_block owns
//	\w \"                escape sequence or pattern source
var notCredentialPrefixes = []string{"$", "%", "{", "[", "/", "~/", "./", "../", "-----", `\`}

// secretShapedValue reports whether value, found under a secret name of the
// given kind, is a credential and not a reference, a template, a literal, a
// count, a description or code.
func secretShapedValue(kind secretNameKind, value string) bool {
	minLength, minEntropy := minCredentialValueLength, minCredentialValueEntropy
	if kind == keyMaterialName {
		minLength, minEntropy = minKeyMaterialValueLength, minKeyMaterialEntropy
	}
	if kind == notSecretName || len(value) < minLength {
		return false
	}
	// A space makes the value a description. A bracket or "(" makes it a
	// template, a generic type or a call. "://" makes it a location.
	if strings.ContainsFunc(value, unicode.IsSpace) || strings.ContainsAny(value, "<>(") || strings.Contains(value, "://") {
		return false
	}
	for _, prefix := range notCredentialPrefixes {
		if strings.HasPrefix(value, prefix) {
			return false
		}
	}
	// No letter: a count, a number, or a mask such as ********.
	if strings.IndexFunc(value, unicode.IsLetter) < 0 {
		return false
	}
	// Sigils around an identifier are not part of it: &str, :password, TOKEN!.
	identifier := strings.TrimRight(strings.TrimLeft(value, "&*:@"), "!?")
	if wordValuePattern.MatchString(identifier) || dottedIdentifierPattern.MatchString(identifier) ||
		indexedIdentifierPattern.MatchString(identifier) || versionValuePattern.MatchString(value) {
		return false
	}
	if kind == keyMaterialName && !strings.ContainsAny(value, "0123456789") {
		return false
	}
	// Few different characters: a filler such as aaaaaaa1.
	return shannonEntropy(value) >= minEntropy
}

// isKeyNameRule reports whether id is one of the rules in this file. They do
// not give way to each other.
func isKeyNameRule(id string) bool {
	return id == keyNameSecretRuleID || id == urlQuerySecretRuleID || id == cookieHeaderRuleID
}

// formatRuleCovers reports whether another secrets rule matches a span that
// contains input[valueStart:valueEnd]. Such a rule knows the format of the
// value, so the key-name rule gives way and the output keeps the more specific
// placeholder (GITHUB_TOKEN=<GITHUB_PAT>, not GITHUB_TOKEN=<SECRET>).
//
// A rule that matches only part of the value does not count: giving way to it
// would leave the rest of the value in the output.
//
// The scan runs from scanStart, the start of the key name, to one character
// past the value. The start is a real boundary, because the name is preceded
// by a character no name holds. The extra character at the end lets a rule that
// requires a boundary after its token see the real one instead of the end of
// the window.
func formatRuleCovers(input string, scanStart, valueStart, valueEnd int) bool {
	windowEnd := min(len(input), valueEnd+1)
	window := input[scanStart:windowEnd]
	for i := range Rules {
		rule := &Rules[i]
		if rule.Category != CategorySecrets || rule.Pattern == nil || isKeyNameRule(rule.ID) {
			continue
		}
		for _, loc := range rule.Pattern.FindAllStringIndex(window, -1) {
			start, end := scanStart+loc[0], scanStart+loc[1]
			if start > valueStart || end < valueEnd {
				continue
			}
			if rule.FilterFn == nil || rule.FilterFn(input[start:end], input, start) {
				return true
			}
		}
	}
	return false
}

// keyNameSecretFilter keeps a key_name_secret match whose value is a
// credential that no format rule covers.
func keyNameSecretFilter(matched, input string, offset int) bool {
	groups := keyNameSecretPattern.FindStringSubmatchIndex(matched)
	if groups == nil || groups[0] != 0 {
		return false
	}
	valueStart, valueEnd := -1, -1
	for _, group := range keyNameSecretValueGroups {
		if groups[2*group] >= 0 {
			valueStart, valueEnd = groups[2*group], groups[2*group+1]
			break
		}
	}
	if valueStart < 0 {
		return false
	}
	prefix, value := matched[groups[2]:groups[3]], matched[valueStart:valueEnd]
	name := strings.TrimRight(prefix, " \t=:\"'\\")
	flagForm := !strings.ContainsAny(prefix[len(name):], "=:")
	if flagForm && strings.HasPrefix(value, "-") {
		// "--password --verbose": the text after the flag is the next flag.
		return false
	}
	if offset > 0 && (input[offset-1] == '?' || input[offset-1] == '&') && prefix == name+"=" {
		// A URL query parameter. url_query_secret owns it and stops the value
		// at the next parameter.
		return false
	}
	if !secretShapedValue(secretNameKindOf(strings.TrimLeft(name, "-")), value) {
		return false
	}
	return !formatRuleCovers(input, offset, offset+valueStart, offset+valueEnd)
}

// urlQuerySecretFilter keeps a url_query_secret match whose value is a
// credential that no format rule covers.
func urlQuerySecretFilter(matched, input string, offset int) bool {
	groups := urlQuerySecretPattern.FindStringSubmatchIndex(matched)
	if groups == nil || groups[0] != 0 {
		return false
	}
	// Group 1 is "?name=" or "&name=".
	name := matched[groups[2]+1 : groups[3]-1]
	value := matched[groups[4]:groups[5]]
	if !secretShapedValue(secretNameKindOf(name), value) {
		return false
	}
	return !formatRuleCovers(input, offset+1, offset+groups[4], offset+groups[5])
}

// secretValueUnderKey reports whether RedactJSON replaces the string value of
// an object key whole. It is the same decision the text rule makes for
// "key": "value": the key ends in a secret word, the value is a credential, and
// no format rule covers the value.
func secretValueUnderKey(key, value string) bool {
	return secretShapedValue(secretNameKindOf(key), value) && !formatRuleCovers(value, 0, 0, len(value))
}
