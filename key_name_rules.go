package redact

import (
	"net/url"
	"regexp"
	"slices"
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
// value, and a password may be short, so its value is held to the lower
// length. A name in keyMaterialNameEndings also names many values that are not
// credentials (a key identifier, an authentication mode), so its value is held
// to the higher length, must hold a digit and must look random. The decision
// table is on secretShapedValue.
const (
	minCredentialValueLength  = 8
	minKeyMaterialValueLength = 20
	minKeyMaterialEntropy     = 3.5
	// maxReferenceDigits is the number of digits a dotted name may hold and
	// still be read as a member access (config.oauth2.token). A dotted value
	// with more digits is a token made of segments.
	maxReferenceDigits = 2
	// maxIdentifierDigits is the number of digits a name made of words may
	// hold and still be read as an identifier: sha256_password holds three.
	maxIdentifierDigits = 3
	// minWordLettersBeforeDigits is the number of letters a word of such a
	// name holds before its digits: "oauth2" is a word, "a1" is not.
	minWordLettersBeforeDigits = 2
	// minPathSegmentCredentialLength is the length from which one segment of a
	// path that mixes letters and digits is read as a credential and not as a
	// file or folder name.
	minPathSegmentCredentialLength = 20
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
// a call or a list. keyNameSecretValues then moves the end of an unquoted
// value where the pattern cannot: back to the start of the next setting
// (nextSettingPattern), or on past an angle bracket that no markup follows
// (unquotedTail).
//
// Forms the pattern does not read, and so leaves in the output: a value in
// Markdown backticks or bold (password: `value`, **password**: value), the
// "=>" separator, an XML element (<password>value</password>), and a value
// with spaces in it (a passphrase).
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
// value alone (see keyNameSecretValues) with the rule's Replacement, the bare
// placeholder; this form serves the recovery path only (see valueRule).
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
// header line or as a JSON member. The header name starts a word, or follows
// an encoded line end in JSON-encoded text (see encodedBreakLetters), where
// the letter of the line end joins the name. The value must start with a cookie name and
// an equals sign, then a first value with no space in it (plain or quoted) or
// a semicolon, so prose after the word "Cookie:" does not match, and the first
// value must not open a template or a variable reference. Whatever follows the
// first pair after a semicolon goes too: the other pairs, and the attributes
// of a Set-Cookie header. After the first pair the value stops at a line end,
// a quote or a backslash, which end the header inside a quoted argument or a
// JSON string.
var cookieHeaderPattern = regexp.MustCompile(
	`(?i)\b(?P<before>[` + encodedBreakLetters + `]?(?:set-)?cookie(?:\\*["'])?:[ \t]*(?:\\*["'])?)[a-z0-9_.\-$]+=` +
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
	// session?.accessToken, oauth2::AccessToken, user->token.
	memberAccessPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|\?\.|::|->)[A-Za-z_$][A-Za-z0-9_$]*)+$`)
	// indexedIdentifierPattern is an identifier that is then indexed:
	// os.environ[, ENV[, argv[.
	indexedIdentifierPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$.]*\[`)
	// versionValuePattern is a version or an image tag: 1.2.3, v0.24.1-rc1.
	versionValuePattern = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+)+(?:[-+._][A-Za-z0-9]+)*$`)
	// relativeFilePattern is a relative path to a file with an extension:
	// config/secrets.yml, src/auth/token.ts.
	relativeFilePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+\.[A-Za-z0-9]{1,5}$`)
	// resourcePathPattern is the name of a stored resource: three or more
	// segments, each one a word or a number, as in
	// projects/123456/secrets/my-secret/versions/1.
	resourcePathPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z_\-]*(?:/(?:[0-9]+|[A-Za-z][A-Za-z_\-]*)){2,}$`)
	// versionWordPattern is the version at the end of a name: v2.
	versionWordPattern = regexp.MustCompile(`^v[0-9]{1,3}$`)
	// shellReferencePattern is a value that reads a variable and holds nothing
	// else: $TOKEN, ${TOKEN}, $(cat token), $1, $HOME/.token, $USER:$PASS,
	// $user->token.
	shellReferencePattern = regexp.MustCompile(`^\$(?:[{(]|[0-9@*#?!$]$|[A-Za-z_][A-Za-z0-9_]*(?:$|->|::|[./:\[]))`)
	// formatReferencePattern is a format verb or a variable between percent
	// signs: %s, %(name)s, %{name}, %TOKEN%.
	formatReferencePattern = regexp.MustCompile(`^%(?:[A-Za-z]$|[({]|[A-Za-z_][A-Za-z0-9_]*%$)`)
	// genericTypePattern is a type with a type argument: Optional<String>.
	genericTypePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*<.+>[?\[\]]*$`)
	// callPattern is a call, up to its closing parenthesis or a member of its
	// result: os.getenv(NAME), secrets.token_hex(16), f(x).value. A value with
	// more text after the closing parenthesis is not a call: aB3xkd(92)LqZw81.
	callPattern = regexp.MustCompile(`^[A-Za-z_$@][A-Za-z0-9_$.:>\-]*\(.*\)(?:[;,]?|\.[A-Za-z_$][^()]*)$`)
	// unquotedCallPattern is an unquoted value that opens with a call, or with
	// a chain of members that ends in a call, and goes on as code does. The end
	// of an unquoted value is only where the pattern stopped, at a space or a
	// quote, so the rest of the expression is often cut off:
	// "token = get_token(client, scope)" gives "get_token(client,", and
	// "token = response.json()["access_token"]" gives "response.json()[".
	// The call is either left open or closed and followed by the end of the
	// value or by a character that is not a letter or a digit (".", "[", ")",
	// ","). A letter or a digit straight after the closing parenthesis is not
	// code: aB3xkd(92)LqZw81.
	unquotedCallPattern = regexp.MustCompile(`^[A-Za-z_$@][A-Za-z0-9_$.:>?\-]*\([^()]*(?:$|\)(?:$|[^A-Za-z0-9]))`)
)

// notCredentialPrefixes open a value that is a reference, a path or an escape
// instead of a credential, however it continues:
//
//	#{name}              interpolation
//	~/x ./x ../x         path to a file
//	\u0041 \w            escape sequence or pattern source
//	arn: vault: file: env:  a reference to where the secret is stored
var notCredentialPrefixes = []string{"#{", "~/", "./", "../", `\`, "arn:", "vault:", "file:", "env:"}

// secretShapedValue reports whether value, found under a secret name of the
// given kind, is a credential and not a reference, a template, a literal, a
// count, a description or code.
//
// whole says that the extent of the value is known: it was quoted, or it is a
// decoded JSON string. An unquoted value is whatever the pattern stopped at, so
// a value that only opens a bracket may be the start of a list or an object;
// a whole value that opens a bracket and does not close it is not one. Space
// around a whole value is not part of it.
//
// The decision, in the order the tests run. The first row that fits decides.
//
//	value                                                    result
//	-------------------------------------------------------  --------
//	shorter than 8 characters (20 for key material)          kept
//	holds a space (a description, a passphrase)              kept
//	holds "://" (a location)                                 kept
//	holds a placeholder this package writes: <USER> <SECRET> kept
//	a reference: $VAR ${VAR} $(cmd) %s %VAR% #{x} arn:...    kept
//	  (a URL query value is tested decoded, so %2B is data)
//	a template or a structure: <token> {name} [a, b] (none)  kept
//	a path: /etc/x ~/x ./x config/x.yml a/123/b              kept
//	a type or a call: Optional<String> getToken() f(x).y     kept
//	  unquoted, a call cut short or followed by code:
//	  a.b().c(8, req.headers.authorization?.split(          kept
//	no letter: digits only, a mask such as ********          kept
//	letters only, as words: hashedPassword, your-api-key     kept
//	a version, a member access, an indexed name              kept
//	words where digits only end a word: oauth2_token,
//	  sha256_password, db-credentials-prod2                  kept
//	key material: no digit, or entropy below 3.5             kept
//	one character fills more than half: aaaaaaa1, ******a*   kept
//	anything else                                            redacted
//
// So under a credential name a value of 8 or more characters that mixes letters
// with digits or symbols is redacted (Summer2024, P4ssw0rd, pass1234,
// P@ssword), unless it is one of the shapes above. Three kinds of weak
// password stay in the output by decision: shorter than 8 characters, letters
// only, digits only.
//
// Known gaps, kept in the output because the shape is ambiguous: a password
// made of words where digits only end a word (Welcome1-Again), a password that
// reads as a variable ($ecretPw99x) or as a call (Pass(123), or unquoted
// Pass(12).x), and a passphrase with spaces. In the other direction an identifier in camel case that holds a
// digit (oauth2Token) is redacted.
func secretShapedValue(kind secretNameKind, value string, whole bool) bool {
	if whole {
		value = strings.TrimSpace(value)
	}
	minLength := minCredentialValueLength
	if kind == keyMaterialName {
		minLength = minKeyMaterialValueLength
	}
	if kind == notSecretName || len(value) < minLength {
		return false
	}
	if strings.ContainsFunc(value, unicode.IsSpace) || strings.Contains(value, "://") {
		return false
	}
	if holdsPlaceholder(value) {
		return false
	}
	if referenceOrStructure(value, whole) {
		return false
	}
	// No letter: a count, a number, or a mask such as ********.
	if strings.IndexFunc(value, unicode.IsLetter) < 0 {
		return false
	}
	// Sigils around an identifier are not part of it: &name, :name, @name, NAME!.
	identifier := strings.TrimRight(strings.TrimLeft(value, "&*:@"), "!?")
	if wordValuePattern.MatchString(identifier) || indexedIdentifierPattern.MatchString(identifier) ||
		versionValuePattern.MatchString(value) || relativeFilePattern.MatchString(value) ||
		resourcePathPattern.MatchString(value) || wordsWithTrailingDigits(identifier) {
		return false
	}
	digits := len(value) - len(strings.Map(dropASCIIDigit, value))
	if memberAccessPattern.MatchString(identifier) && digits <= maxReferenceDigits {
		return false
	}
	if kind == keyMaterialName {
		return digits > 0 && shannonEntropy(value) >= minKeyMaterialEntropy
	}
	return !isFiller(value)
}

// placeholderPattern is the shape of the placeholders this package writes.
var placeholderPattern = regexp.MustCompile(`<[A-Z][A-Z0-9_]*>`)

// ruleSetPlaceholders are the placeholders the rules and the path stage write
// into the output: <SECRET>, <USER>, <PATH>. A value that holds one has been
// redacted already, so a second pass leaves it as it is: the first pass kept
// "abc12345/Users/jane/x.txt" as a path and replaced the account name, and
// the second must not then read "abc12345/Users/" as a credential.
//
// The set is read from the rule table in init, after every package variable
// is set: the value test is part of the rule table, so a variable built from
// the table here would be a cycle.
var ruleSetPlaceholders map[string]bool

func init() {
	ruleSetPlaceholders = map[string]bool{privatePathPlaceholder: true}
	for _, rule := range Rules {
		for _, placeholder := range placeholderPattern.FindAllString(rule.Replacement, -1) {
			ruleSetPlaceholders[placeholder] = true
		}
	}
}

// holdsPlaceholder reports whether value holds one of ruleSetPlaceholders.
func holdsPlaceholder(value string) bool {
	if !strings.Contains(value, "<") {
		return false
	}
	for _, placeholder := range placeholderPattern.FindAllString(value, -1) {
		if ruleSetPlaceholders[placeholder] {
			return true
		}
	}
	return false
}

// startsWithPlaceholder reports whether text starts with one of
// ruleSetPlaceholders.
func startsWithPlaceholder(text string) bool {
	location := placeholderPattern.FindStringIndex(text[:min(len(text), maxPlaceholderLength)])
	return location != nil && location[0] == 0 && ruleSetPlaceholders[text[:location[1]]]
}

// maxPlaceholderLength bounds how much of the text startsWithPlaceholder
// reads. Every placeholder of this package is shorter.
const maxPlaceholderLength = 64

// referenceOrStructure reports whether value is a reference to a value kept
// elsewhere, a template, the start of a structure, a path, a type or a call.
func referenceOrStructure(value string, whole bool) bool {
	for _, prefix := range notCredentialPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	last := value[len(value)-1]
	switch value[0] {
	case '$':
		// Quoted or not, a value that reads a variable and holds nothing else.
		// $2a$10$N9qo8uLOickgx2ZMRZoMye is data.
		return shellReferencePattern.MatchString(value)
	case '%':
		return !whole || formatReferencePattern.MatchString(value)
	case '{':
		// {name}, {{ .Value }}, or the start of an object.
		return !whole || last == '}'
	case '[':
		// [REDACTED], or the start of a list.
		return !whole || last == ']'
	case '(':
		// (none), (optional).
		return !whole || last == ')'
	case '<':
		// <token>, <your-api-key>.
		return last == '>'
	case '/':
		return absolutePath(value)
	}
	return genericTypePattern.MatchString(value) || callPattern.MatchString(value) || (!whole && unquotedCallPattern.MatchString(value))
}

// absolutePath reports whether a value that starts with a slash is a path to a
// file and not a credential in the base64 alphabet, which also uses the slash.
// It is a credential when it holds "+" or "=", or when one segment is long and
// mixes letters and digits: /a8Fk29dLq0Pz71Xn5Rv3Tb6Yc4Wm2Qe8Hs1Jg.
func absolutePath(value string) bool {
	if strings.ContainsAny(value, "+=") {
		return false
	}
	for segment := range strings.SplitSeq(value, "/") {
		if len(segment) >= minPathSegmentCredentialLength && strings.ContainsFunc(segment, isASCIIDigitRune) && strings.ContainsFunc(segment, unicode.IsLetter) {
			return false
		}
	}
	return true
}

// wordsWithTrailingDigits reports whether value is a name made of two or more
// words joined by underscores or hyphens, in which digits only end a word:
// oauth2_token, sha256_password, base64_token, db-credentials-prod2,
// oauth2-authorization-code. A generated credential and most passwords hold a
// digit somewhere else, or hold more digits.
//
// At least one word holds no digit, every word with digits starts with two or
// more letters, and the name holds three digits at most. A version at the end
// (v2) is not counted.
func wordsWithTrailingDigits(value string) bool {
	words := strings.FieldsFunc(value, func(r rune) bool { return r == '_' || r == '-' })
	if len(words) > 1 && versionWordPattern.MatchString(words[len(words)-1]) {
		words = words[:len(words)-1]
	}
	if len(words) < 2 {
		return false
	}
	plain, digits := 0, 0
	for _, word := range words {
		letters := strings.IndexFunc(word, func(r rune) bool { return !isASCIILetterRune(r) })
		if letters < 0 {
			plain++
			continue
		}
		if letters < minWordLettersBeforeDigits || !isDigits(word[letters:]) {
			return false
		}
		digits += len(word) - letters
	}
	return plain > 0 && digits > 0 && digits <= maxIdentifierDigits
}

// isFiller reports whether one character makes up more than half of value:
// aaaaaaa1, ******a*, xxxx-xxxx-xxx1.
func isFiller(value string) bool {
	counts := make(map[rune]int)
	total, most := 0, 0
	for _, r := range value {
		counts[r]++
		total++
		most = max(most, counts[r])
	}
	return 2*most > total
}

func isASCIIDigitRune(r rune) bool { return r >= '0' && r <= '9' }

func isASCIILetterRune(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

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
// start of another setting (see nextSettingPattern) is cut there, so each
// setting on the line is judged by its own name:
// "password=abc12345,token=def67890" holds two values.
//
// The cuts are found once, and each setting between two cuts is read on its
// own, so the time taken follows the length of the match: a line of thousands
// of settings with no space between them is read once, not once per setting.
func keyNameSecretValues(matched, input string, offset int) []valueSpan {
	pair, ok := keyNamePairAt(input, offset, keyNameSecretPattern.FindStringSubmatchIndex(matched))
	if !ok {
		return nil
	}
	if !pair.bare {
		return appendKeyNameValue(nil, input, pair)
	}
	end := pair.valueEnd
	if end == offset+len(matched) {
		// The pattern stops an unquoted value at an angle bracket.
		end += len(unquotedTail(input[end:]))
	}
	valueStart := pair.valueStart
	if strings.HasSuffix(input[:pair.pairStart], "://") {
		// The user and password of a URL, as in a clone URL whose user is
		// x-access-token. The password ends at the "@" before the host.
		if at := strings.IndexByte(input[valueStart:end], '@'); at >= 0 {
			end = valueStart + at
		}
	}
	cuts := nextSettingPattern.FindAllStringIndex(input[valueStart:end], -1)
	var spans []valueSpan
	for k := 0; ; k++ {
		pair.valueEnd = end
		if k < len(cuts) {
			pair.valueEnd = valueStart + cuts[k][0]
		}
		spans = appendKeyNameValue(spans, input, pair)
		if k == len(cuts) {
			return spans
		}
		// The next setting starts after the comma or semicolon and ends at
		// the next cut. It holds no space and no quote, because the unquoted
		// value it was cut from holds none.
		start := valueStart + cuts[k][0] + 1
		stop := end
		if k+1 < len(cuts) {
			stop = valueStart + cuts[k+1][0]
		}
		next, found := keyNamePairAt(input, start, keyNameSecretPattern.FindStringSubmatchIndex(input[start:stop]))
		if !found {
			pair = keyNamePair{}
			continue
		}
		pair = next
	}
}

// keyNamePair is one name and its value in a key_name_secret match, as
// positions in the input.
type keyNamePair struct {
	pairStart            int
	nameStart, nameEnd   int
	valueStart, valueEnd int
	bare, flag, present  bool
}

// keyNamePairAt reads the groups of keyNameSecretPattern, found in the input
// at offset, as a keyNamePair.
func keyNamePairAt(input string, offset int, groups []int) (keyNamePair, bool) {
	if groups == nil {
		return keyNamePair{}, false
	}
	group := func(index int) (start, end int, ok bool) {
		if groups[2*index] < 0 {
			return 0, 0, false
		}
		return offset + groups[2*index], offset + groups[2*index+1], true
	}
	pair := keyNamePair{pairStart: offset + groups[0], present: true}
	found := false
	for _, index := range keyNameValueGroups {
		if start, end, ok := group(index); ok {
			pair.valueStart, pair.valueEnd, found = start, end, true
			break
		}
	}
	if !found {
		return keyNamePair{}, false
	}
	_, _, pair.bare = group(keyNameBareGroup)
	if pair.nameStart, pair.nameEnd, pair.flag = group(keyNameFlagGroup); !pair.flag {
		pair.nameStart, pair.nameEnd, _ = group(keyNameNameGroup)
	}
	return pair, true
}

// appendKeyNameValue appends the value of pair to spans when it is a
// credential.
func appendKeyNameValue(spans []valueSpan, input string, pair keyNamePair) []valueSpan {
	if !pair.present || pair.valueStart >= pair.valueEnd {
		return spans
	}
	value := input[pair.valueStart:pair.valueEnd]
	name := input[pair.nameStart:pair.nameEnd]
	if pair.flag {
		// "--password --verbose": the text after the flag is the next flag.
		// "--secret id=npmrc,src=.npmrc": a list of settings, not a value.
		if strings.HasPrefix(value, "-") || flagSettingPattern.MatchString(value) {
			return spans
		}
	} else {
		tight := pair.nameEnd < len(input) && input[pair.nameEnd] == '='
		if before := pair.pairStart - 1; pair.bare && tight && before >= 0 && (input[before] == '?' || input[before] == '&') {
			// An unquoted URL query parameter. url_query_secret owns it and
			// stops the value at the next parameter.
			return spans
		}
	}
	if pair.bare && startsWithPlaceholder(input[pair.valueEnd:]) {
		// The value stopped at a placeholder an earlier pass wrote:
		// "token=abc12345/Users/<USER>/x.txt". It was judged then.
		return spans
	}
	kind := secretNameKindOf(name)
	if !pair.flag && messageAbout(input, pair.nameStart, name) {
		kind = keyMaterialName
	}
	if !secretShapedValue(kind, value, !pair.bare) {
		return spans
	}
	return append(spans, valueSpan{start: pair.valueStart, end: pair.valueEnd, construct: pair.pairStart})
}

// markupAfterValuePattern is an angle bracket that ends an unquoted value: a
// closing tag, a comment or instruction, or a whole tag or template.
var markupAfterValuePattern = regexp.MustCompile(`^<[/!?]|<[^<>]*>`)

// maxTailLookahead bounds how far unquotedTail reads past the pattern match,
// so that a long line with an angle bracket after every value is still read in
// time that follows its length. A value continues past an angle bracket for at
// most this many bytes.
const maxTailLookahead = 256

// unquotedTail returns what an unquoted value continues with when the pattern
// stopped it at "<" or ">": the text up to the next space, quote or backslash.
// rest is the input after the pattern match. The pattern stops there so that
// "token=abc<br>" and "<password>abc</password>" keep their markup; a value
// such as aB3xkd92Lq<Zw81 has no markup after it and continues. The tail is
// empty when it holds a tag, or when the line goes on to close one with ">".
// It reads no more than maxTailLookahead bytes of rest.
//
// The tail ends as the unquoted value does: not in the punctuation that closes
// a call or a list (see closingPunctuation), so "if (password=abc12345<x)"
// keeps its ")". A shell redirect (>>file, >&2, >|file) is not part of the
// value.
func unquotedTail(rest string) string {
	if rest == "" || (rest[0] != '<' && rest[0] != '>') {
		return ""
	}
	if len(rest) > 1 && rest[0] == '>' && strings.IndexByte(">&|", rest[1]) >= 0 {
		return ""
	}
	rest = rest[:min(len(rest), maxTailLookahead)]
	tail := rest
	if end := strings.IndexAny(rest, " \t\r\n\"'`\\"); end >= 0 {
		tail = rest[:end]
	}
	if markupAfterValuePattern.MatchString(tail) {
		return ""
	}
	line := rest[len(tail):]
	if end := strings.IndexAny(line, "\r\n"); end >= 0 {
		line = line[:end]
	}
	if strings.Contains(tail, "<") && strings.Contains(line, ">") {
		return ""
	}
	if tail = strings.TrimRight(tail, closingPunctuation); len(tail) == 1 {
		// Only the angle bracket is left.
		return ""
	}
	return tail
}

// closingPunctuation closes a call or a list. An unquoted value does not end
// in it: keyNameSecretPattern leaves it out of the last character of the
// value, and unquotedTail takes it off the end of the tail.
const closingPunctuation = ",;)]}"

// messageSubject is the one name that messages from parsers and validators
// use for something that is not a credential, and messageWords are the words
// such a message puts before it: "Unexpected token: identifier",
// "invalid token: abc (expected number)".
const messageSubject = "token"

var messageWords = []string{
	"unexpected", "expected", "invalid", "unknown", "unrecognized", "unrecognised",
	"illegal", "bad", "malformed", "missing", "stray", "extra",
	"next", "previous", "current", "first", "last",
}

// messageAbout reports whether the name at input[nameStart:] is the subject of
// a message and not the name of a setting: the name is "token" and the word
// before it is one of messageWords. Its value is then held to the test for key
// material, so a real token quoted in an error message is still redacted and a
// short word is not.
func messageAbout(input string, nameStart int, name string) bool {
	if !strings.EqualFold(name, messageSubject) {
		return false
	}
	before := strings.TrimRight(input[:nameStart], " \t")
	if len(before) == nameStart {
		return false
	}
	word := len(before)
	for word > 0 && isASCIILetterRune(rune(before[word-1])) {
		word--
	}
	return slices.Contains(messageWords, strings.ToLower(before[word:]))
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
	value := matched[valueStart:valueEnd]
	// In a URL a percent sign and two hex digits are one encoded character,
	// so the value is tested as it reads decoded: %2BaB3x... is +aB3x....
	// A value that does not decode (%s, %TOKEN%) is tested as it is.
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	if !secretShapedValue(secretNameKindOf(name), value, false) {
		return nil
	}
	return []valueSpan{{start: offset + valueStart, end: offset + valueEnd, construct: offset}}
}

// cookieHeaderValues returns the part of a cookie_header match after the
// header name: the cookie pairs and attributes.
func cookieHeaderValues(matched, input string, offset int) []valueSpan {
	groups := cookieHeaderPattern.FindStringSubmatchIndex(matched)
	if groups == nil || groups[0] != 0 {
		return nil
	}
	// Neither header name starts with one of encodedBreakLetters, so such a
	// letter at the start is the one the pattern lets stand before the name.
	if strings.IndexByte(encodedBreakLetters, matched[0]|0x20) >= 0 && !endsEncodedBreak(input, offset+1) {
		return nil
	}
	return []valueSpan{{start: offset + groups[2*cookieHeaderBeforeGroup+1], end: offset + len(matched), construct: offset}}
}

// secretValueUnderKey reports whether the string value of an object key is a
// credential by the test of the text rule for "key": "value": the key ends in
// a secret word and the value, whose extent is known, is shaped like a
// credential.
func secretValueUnderKey(key, value string) bool {
	return secretShapedValue(secretNameKindOf(key), value, true)
}
