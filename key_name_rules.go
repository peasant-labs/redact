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
// The name lists and the value test live here, in one place. The text rules
// (key_name_secret, url_query_secret) and RedactJSON all call secretNameKindOf
// and secretShapedValue, so the three forms apply one test to a name and a
// value.
//
// Each rule in this file reports the value as its match, not the name and the
// value (see valueFinder in detect.go). Detection then settles every overlap
// with another rule's match, so a rule that knows the format of the value gives
// the output its more specific placeholder, and no match of another rule is
// lost because one of these rules matched first.

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
	// minSymbolValueEntropy replaces minCredentialValueEntropy for a value that
	// holds a symbol. No identifier holds one, so only a filler such as
	// ******a* has to be kept out, and P@ssw0rd must not be.
	minSymbolValueEntropy = 2.0
	// maxReferenceDigits is the number of digits a dotted name may hold and
	// still be read as a member access (config.oauth2.token). A dotted value
	// with more digits is a token made of segments.
	maxReferenceDigits = 2
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
// from the lists, so the patterns and secretNameKindOf read one definition.
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

// escapedCharPattern is a backslash and the character it escapes, inside an
// unquoted value: the "\!" of a shell command. A backslash before n, r, t or a
// quote is left out, because in a JSON string those end the line or the string
// and are not part of the value.
const escapedCharPattern = `\\[^nrt"'\s]`

// keyNameSecretPattern matches a secret name, a separator and a value on one
// line. It uses no lookaround and no backreference.
//
// The part before the value is one of two forms, and the group that matched
// says which:
//
//	flag    --name value
//	name    NAME=value   NAME: value   NAME := value   "name": "value"
//
// The value is one of four alternatives. Each keeps its own quotes in groups of
// their own, so the replacement can put them back:
//
//	dq       "value"    a double-quoted string, escapes allowed inside
//	esc      \"value\"  the same member inside a JSON string, quotes escaped
//	sq       'value'    a single-quoted string
//	bare     value      unquoted
//
// A quoted value holds no space: a quoted text with spaces is a description,
// and the pattern does not match it. An unquoted value does not start with =,
// < or > (so ==, => and <template> are not values). It stops at a space, a
// quote, < and >, and at the encoded line end, tab or quote of a JSON string
// (see escapedCharPattern), and it does not end in the punctuation that closes
// a call or a list.
var keyNameSecretPattern = regexp.MustCompile(
	`(?i)(?P<before>--(?P<flag>` + secretNamePattern + `)[ \t]+|(?P<name>` + secretNamePattern + `)(?:\\*["'])?[ \t]*(?::=|[=:])[ \t]*)` +
		`(?:(?P<dqo>")(?P<dq>(?:[^"\s\\]|\\[^\s])+)(?P<dqc>")` +
		`|(?P<esco>\\+")(?P<esc>[^"\s\\]+)(?P<escc>\\+")` +
		`|(?P<sqo>')(?P<sq>[^'\s]+)(?P<sqc>')` +
		"|(?P<bare>[^\\s\"'`<>=\\\\](?:(?:[^\\s\"'`<>\\\\]|" + escapedCharPattern + ")*(?:[^\\s\"'`<>\\\\,;)\\]}]|" + escapedCharPattern + "))?))")

// nextSettingPattern is where an unquoted value ends although the pattern runs
// on: a comma or a semicolon and then the name of the next setting, as in
// "password=abc12345,user=jane" and "Password=abc12345;Encrypt=true". RE2 has
// no lookahead, so the pattern cannot stop there itself, and
// keyNameSecretValues cuts the value. A password that holds ",name=" is cut
// short; the text after the cut is read as the next setting.
var nextSettingPattern = regexp.MustCompile(`[,;][A-Za-z_][A-Za-z0-9_.\-]*=`)

// keyNameSecretReplacement replaces a whole pattern match: it keeps the text
// before the value and whichever pair of quotes matched. Detection replaces the
// value alone (see keyNameSecretValues); this form serves the recovery path.
const keyNameSecretReplacement = "${before}${dqo}${esco}${sqo}" + keyNameSecretPlaceholder + "${dqc}${escc}${sqc}"

// Group indices of keyNameSecretPattern, resolved once by name.
var (
	keyNameFlagGroup   = keyNameSecretPattern.SubexpIndex("flag")
	keyNameNameGroup   = keyNameSecretPattern.SubexpIndex("name")
	keyNameBareGroup   = keyNameSecretPattern.SubexpIndex("bare")
	keyNameValueGroups = [...]int{
		keyNameSecretPattern.SubexpIndex("dq"),
		keyNameSecretPattern.SubexpIndex("esc"),
		keyNameSecretPattern.SubexpIndex("sq"),
		keyNameBareGroup,
	}
)

// urlQuerySecretPattern matches a secret-named parameter in a URL query. The
// value stops at the next parameter or the fragment, which the general pattern
// cannot do without cutting a password that contains "&".
var urlQuerySecretPattern = regexp.MustCompile(
	"(?i)(?P<before>[?&](?P<name>" + secretNamePattern + ")=)(?P<value>[^\\s\"'`<>&#\\\\]+)")

var (
	urlQueryNameGroup  = urlQuerySecretPattern.SubexpIndex("name")
	urlQueryValueGroup = urlQuerySecretPattern.SubexpIndex("value")
)

// cookieHeaderPattern matches the value of a Cookie or Set-Cookie header, as a
// header line or as a JSON member. The value must start with a cookie name and
// an equals sign, then a first value with no space in it (plain or quoted) or
// a semicolon, so prose after the word "Cookie:" does not match, and the first
// value must not open a template or a variable reference. Whatever follows the
// first pair after a semicolon goes too: the other pairs, and the attributes
// of a Set-Cookie header. After the first pair the value stops at a line end,
// a quote or a backslash, which end the header inside a quoted argument or a
// JSON string.
var cookieHeaderPattern = regexp.MustCompile(
	`(?i)\b(?P<before>(?:set-)?cookie(?:\\*["'])?:[ \t]*(?:\\*["'])?)[a-z0-9_.\-$]+=` +
		`(?:(?:[^\s;"'<${\\][^\s;"'\\]*|\\*"[^\s;"'<${\\][^\s;"'\\]*\\*")(?:;[^\r\n"'\\]*)?|;[^\r\n"'\\]*)`)

var cookieHeaderBeforeGroup = cookieHeaderPattern.SubexpIndex("before")

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
	// hyphens between them, and an optional version at the end: an identifier
	// (hashedPassword, user_password, user_token_v2), a literal or type name
	// (null, string), a placeholder (your-api-key), or the name of another
	// object (postgres-credentials-v1).
	wordValuePattern = regexp.MustCompile(`^[A-Za-z_\-]+(?:[_\-]v[0-9]{1,3})?$`)
	// memberAccessPattern is a member access or an environment read:
	// process.env.TOKEN, request.body.token, var.database_password,
	// session?.accessToken, oauth2::AccessToken.
	memberAccessPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|\?\.|::)[A-Za-z_$][A-Za-z0-9_$]*)+$`)
	// indexedIdentifierPattern is an identifier that is then indexed:
	// os.environ[, ENV[, argv[.
	indexedIdentifierPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$.]*\[`)
	// versionValuePattern is a version or an image tag: 1.2.3, v0.24.1-rc1.
	versionValuePattern = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+)+(?:[-+._][A-Za-z0-9]+)*$`)
	// relativeFilePattern is a relative path to a file with an extension:
	// config/secrets.yml, src/auth/token.ts.
	relativeFilePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+\.[A-Za-z0-9]{1,5}$`)
	// identifierCharsPattern is a value no symbol appears in.
	identifierCharsPattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)
)

// notCredentialPrefixes open a value that is a reference, a template, a
// structure, a path or an escape instead of a credential:
//
//	$VAR ${VAR} $(cmd)   variable reference or command substitution
//	%s %(name)s %VAR%    format verb or variable reference
//	#{name}              interpolation
//	{name} {{ .Value }}  template or the start of an object
//	[REDACTED] [a, b]    marker or the start of a list
//	/etc/x ~/x ./x ../x  path to a file
//	\u0041 \w            escape sequence or pattern source
//	arn: vault: file: env:  a reference to where the secret is stored
var notCredentialPrefixes = []string{"$", "%", "#{", "{", "[", "/", "~/", "./", "../", `\`, "arn:", "vault:", "file:", "env:"}

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
	// Sigils around an identifier are not part of it: &name, :name, @name, NAME!.
	identifier := strings.TrimRight(strings.TrimLeft(value, "&*:@"), "!?")
	if wordValuePattern.MatchString(identifier) || indexedIdentifierPattern.MatchString(identifier) ||
		versionValuePattern.MatchString(value) || relativeFilePattern.MatchString(value) {
		return false
	}
	digits := len(value) - len(strings.Map(dropASCIIDigit, value))
	if memberAccessPattern.MatchString(identifier) && digits <= maxReferenceDigits {
		return false
	}
	if kind == keyMaterialName {
		if digits == 0 {
			return false
		}
	} else if !identifierCharsPattern.MatchString(value) {
		minEntropy = minSymbolValueEntropy
	}
	// Few different characters: a filler such as aaaaaaa1.
	return shannonEntropy(value) >= minEntropy
}

func isASCIIDigitRune(r rune) bool { return r >= '0' && r <= '9' }

// dropASCIIDigit removes digits; strings.Map drops a rune mapped below zero.
// A digit is one byte, so the byte lengths before and after differ by the
// number of digits.
func dropASCIIDigit(r rune) rune {
	if isASCIIDigitRune(r) {
		return -1
	}
	return r
}

// isKeyNameRule reports whether id is one of the rules in this file. They come
// after every format rule in the rule table, so that a format rule wins when
// its match and a value match span the same text.
func isKeyNameRule(id string) bool {
	return id == keyNameSecretRuleID || id == urlQuerySecretRuleID || id == cookieHeaderRuleID
}

// keyNameSecretValues returns the credential values in one key_name_secret
// match. It is usually one value. An unquoted value that runs through the
// start of another setting (see nextSettingPattern) is cut there, and the rest
// of the match is read again, so each setting on the line is judged by its own
// name: "password=abc12345,token=def67890" holds two values.
func keyNameSecretValues(matched, input string, offset int) []valueSpan {
	var spans []valueSpan
	for next := 0; next < len(matched); {
		base := next
		groups := keyNameSecretPattern.FindStringSubmatchIndex(matched[base:])
		if groups == nil {
			break
		}
		group := func(index int) (start, end int, ok bool) {
			if groups[2*index] < 0 {
				return 0, 0, false
			}
			return base + groups[2*index], base + groups[2*index+1], true
		}
		pairStart := base + groups[0]
		next = base + groups[1]
		valueStart, valueEnd := -1, -1
		for _, index := range keyNameValueGroups {
			if start, end, ok := group(index); ok {
				valueStart, valueEnd = start, end
				break
			}
		}
		if valueStart < 0 {
			break
		}
		_, _, bare := group(keyNameBareGroup)
		if bare {
			if cut := nextSettingPattern.FindStringIndex(matched[valueStart:valueEnd]); cut != nil {
				valueEnd = valueStart + cut[0]
				next = valueEnd + 1
			}
		}
		value := matched[valueStart:valueEnd]
		nameStart, nameEnd, flagForm := group(keyNameFlagGroup)
		if flagForm {
			// "--password --verbose": the text after the flag is the next flag.
			// "--secret id=npmrc,src=.npmrc": a list of settings, not a value.
			if strings.HasPrefix(value, "-") || flagSettingPattern.MatchString(value) {
				continue
			}
		} else {
			nameStart, nameEnd, _ = group(keyNameNameGroup)
			tight := nameEnd < len(matched) && matched[nameEnd] == '='
			if before := offset + pairStart - 1; bare && tight && before >= 0 && (input[before] == '?' || input[before] == '&') {
				// An unquoted URL query parameter. url_query_secret owns it and
				// stops the value at the next parameter.
				continue
			}
		}
		if secretShapedValue(secretNameKindOf(matched[nameStart:nameEnd]), value) {
			spans = append(spans, valueSpan{offset + valueStart, offset + valueEnd})
		}
	}
	return spans
}

// flagSettingPattern is a flag value that is itself a setting: id=npmrc.
var flagSettingPattern = regexp.MustCompile(`^[A-Za-z_]+=`)

// urlQuerySecretValues returns the value of a url_query_secret match when it
// is a credential.
func urlQuerySecretValues(matched, input string, offset int) []valueSpan {
	groups := urlQuerySecretPattern.FindStringSubmatchIndex(matched)
	if groups == nil || groups[0] != 0 {
		return nil
	}
	name := matched[groups[2*urlQueryNameGroup]:groups[2*urlQueryNameGroup+1]]
	valueStart, valueEnd := groups[2*urlQueryValueGroup], groups[2*urlQueryValueGroup+1]
	if !secretShapedValue(secretNameKindOf(name), matched[valueStart:valueEnd]) {
		return nil
	}
	return []valueSpan{{offset + valueStart, offset + valueEnd}}
}

// cookieHeaderValues returns the part of a cookie_header match after the
// header name: the cookie pairs and attributes.
func cookieHeaderValues(matched, input string, offset int) []valueSpan {
	groups := cookieHeaderPattern.FindStringSubmatchIndex(matched)
	if groups == nil || groups[0] != 0 {
		return nil
	}
	return []valueSpan{{offset + groups[2*cookieHeaderBeforeGroup+1], offset + len(matched)}}
}

// secretValueUnderKey reports whether the string value of an object key is a
// credential by the test of the text rule for "key": "value": the key ends in
// a secret word and the value is shaped like a credential.
func secretValueUnderKey(key, value string) bool {
	return secretShapedValue(secretNameKindOf(key), value)
}
