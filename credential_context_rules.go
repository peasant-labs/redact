package redact

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Rules that find a credential by the construct around it: an Authorization
// header with a scheme other than Bearer or Basic, the user option of a curl
// command, and the private members of a JSON Web Key. The filter for the token
// rules that have only a documented prefix is here too.

const (
	authorizationTokenRuleID = "authorization_token"
	curlUserPasswordRuleID   = "curl_user_password"
	jwkPrivateMemberRuleID   = "jwk_private_member"

	curlUserPasswordPlaceholder = "<CREDENTIALS>"
	jwkPrivateMemberPlaceholder = "<JWK_PRIVATE_KEY>"
)

// prefixTokenRule builds a rule that knows only the prefix of a token. A prefix
// such as hf_ or vcr_ also starts ordinary identifiers (hf_hub_download,
// vcr_cassette_library_dir), so two things must hold for a match:
//
//   - The prefix starts a word. "usbp_" does not hold the prefix "sbp_". The
//     letter of an encoded line end or tab before the prefix does not make a
//     word: a token on its own line in JSON-encoded text follows "\n".
//   - The body holds a digit. A generated token of 20 or more characters
//     nearly always does; an identifier made of words does not.
//
// The second test leaves a token made of letters alone unredacted by these
// rules. That is the price of not redacting code.
//
// The rule has a value finder (see valueRules in detect.go), because the token
// is not always the whole pattern match: in "task-admin-sk-admin-..." the
// pattern first matches from the "sk-admin-" that ends the word "task-admin-",
// and the token starts at the second one.
func prefixTokenRule(id, pattern, placeholder string) Rule {
	compiled := regexp.MustCompile(pattern)
	find := prefixTokenValues(compiled)
	valueRules[compiled] = valueRule{find: find, placeholder: placeholder, knowsFormat: true}
	return Rule{ID: id, Category: CategorySecrets, Pattern: compiled, Replacement: placeholder, FilterFn: hasValue(find)}
}

// prefixTokenValues finds the token in one match of a prefix-token pattern. It
// is the match itself when the prefix starts a word. Otherwise the prefix is
// the end of a longer word, and the token is the first match of the pattern
// inside this one that does start a word.
func prefixTokenValues(pattern *regexp.Regexp) valueFinder {
	return func(matched, input string, offset int) []valueSpan {
		start, end := 0, len(matched)
		for {
			at := offset + start
			if at == 0 || !isWordByte(input[at-1]) || endsEncodedBreak(input, at) {
				if strings.IndexFunc(matched[start:end], isASCIIDigitRune) < 0 {
					return nil
				}
				return []valueSpan{{at, offset + end}}
			}
			inside := pattern.FindStringIndex(matched[start+1:])
			if inside == nil {
				return nil
			}
			start, end = start+1+inside[0], start+1+inside[1]
		}
	}
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// encodedBreakLetters are the letters that, after a backslash, make a line
// end, a carriage return or a tab in a JSON string. A pattern that needs the
// start of a word or of a line lets one of them stand before its first word,
// and its filter then checks with endsEncodedBreak that the letter really
// follows a backslash: in JSON-encoded text the letter is not part of the word
// after it. The letter is optional in the pattern, and not an alternative at
// its start, because that keeps the scan as fast as it was without it.
const encodedBreakLetters = "nrt"

// endsEncodedBreak reports whether input[:end] ends in an encoded line end,
// carriage return or tab. The backslash must itself be unescaped: in "\\n"
// the two backslashes are one literal backslash and the "n" is a letter.
func endsEncodedBreak(input string, end int) bool {
	if end < 2 || strings.IndexByte(encodedBreakLetters, input[end-1]) < 0 {
		return false
	}
	return unescapedBackslash(input, end-2)
}

// unescapedBackslash reports whether input[at] is a backslash that an odd run
// of backslashes ends, so that it escapes the character after it.
func unescapedBackslash(input string, at int) bool {
	run := 0
	for at >= 0 && input[at] == '\\' {
		run++
		at--
	}
	return run%2 == 1
}

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

// curlBooleanShortOptions are the one-letter options of curl that take no
// value, so they can stand before "u" in one bundle: -sSu, -kLu.
// https://curl.se/docs/manpage.html
//
// A letter that takes a value ends the bundle, and what follows it is that
// value: "-menu" is "-m enu", not a bundle that ends in "-u".
const curlBooleanShortOptions = `#0-46aBfgGiIjJklLMnNOpqRsSvVZ`

// curlUserPasswordPattern matches the user option of a command line and takes
// the user and the password together:
//
//	-u, --user <user:password>
//	https://curl.se/docs/manpage.html#-u
//	("The username and passwords are split up on the first colon")
//
// Forms: -u pair, -upair, a short option bundled after others (-sSu pair),
// --user pair, --user=pair, and the option and the pair as two members of an
// argument list ("-u", "pair"). The long option needs the space or the equals
// sign, so --user-agent is not read as --user. The pair is double-quoted,
// single-quoted or bare. A bare pair uses the character class of an unquoted
// key-name value: it stops at a space, a quote, a backtick, or the encoded
// line end and tab that a JSON string carries, and it does not end in the
// punctuation that closes a call or a list. The password may be empty.
//
// The whole pair is replaced, not the password alone. A token is often sent as
// the user name with a dummy or empty password, and a rule that kept the user
// name would keep the token.
//
// The rule is a value rule (see valueRules in detect.go): its match is the
// pair, so it does not displace a match of another rule around it.
// curlUserPasswordValues does the rest: other commands use -u for other things
// (sort -u, git push -u, docker run -u), so a match is kept only when the
// command it belongs to is curl.
var curlUserPasswordPattern = regexp.MustCompile(
	`(?P<before>(?:-[` + curlBooleanShortOptions + `]{0,6}u(?:[ \t]+|\\*["'],[ \t]*)?|--user(?:[ \t]+|=|\\*["'],[ \t]*)))` +
		`(?:(?P<dqo>\\*")(?P<dq>[^"\\:]*:[^"\\]*)(?P<dqc>\\*")` +
		`|(?P<sqo>')(?P<sq>[^':]*:[^']*)(?P<sqc>')` +
		"|(?P<bare>[^\\s:\"'`\\\\]*:(?:(?:[^\\s\"'`\\\\]|" + escapedCharPattern + ")*(?:[^\\s\"'`\\\\,;)\\]}]|" + escapedCharPattern + "))?))")

// curlUserPasswordReplacement replaces a whole pattern match: it keeps the
// option and whichever quotes matched. Detection replaces the pair alone; this
// form serves the recovery path.
const curlUserPasswordReplacement = "${before}${dqo}${sqo}" + curlUserPasswordPlaceholder + "${dqc}${sqc}"

// The pair groups of curlUserPasswordPattern, resolved once by name.
var (
	curlBarePairGroup = curlUserPasswordPattern.SubexpIndex("bare")
	curlPairGroups    = [...]int{
		curlUserPasswordPattern.SubexpIndex("dq"),
		curlUserPasswordPattern.SubexpIndex("sq"),
		curlBarePairGroup,
	}
)

// curlCommandPattern is the command word itself, not a longer word around it.
var curlCommandPattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.\-])curl(?:\.exe)?(?:[\s"',\\]|$)`)

// placeholderPasswords are the words documentation writes in place of a
// password: curl -u user:password.
var placeholderPasswords = []string{"password", "passwd", "pass", "pwd", "secret", "token", "key", "apikey", "api_key"}

// notCredentialStarts open a password that is a variable reference or a
// template: $PASS, ${PASS}, <password>, {password}, %s.
const notCredentialStarts = "$<{%"

// maxCommandLookback bounds how far back curlUserPasswordValues looks for the
// command word.
const maxCommandLookback = 4096

// curlUserPasswordValues returns the pair of a match whose option belongs to a
// curl command and whose pair holds a credential:
//
//	pair                       result
//	-------------------------  --------
//	user:literal               redacted
//	$USER:literal              redacted   (the password is in the text)
//	token:  (empty password)   redacted when the user name passes the test
//	                           for key material: 20 characters, a digit
//	user:   (empty password)   kept       (curl asks for the password)
//	user:$PASS user:<pw> ...   kept       (a reference or a template)
//	user:password user:token   kept       (see placeholderPasswords)
//	1000:1000                  kept       (a user and group number)
func curlUserPasswordValues(matched, input string, offset int) []valueSpan {
	// The option starts an argument: it follows the start of the text, a
	// space, a quote, or the punctuation of an argument list.
	if offset > 0 && !strings.ContainsRune(" \t\r\n\"'[,", rune(input[offset-1])) {
		return nil
	}
	groups := curlUserPasswordPattern.FindStringSubmatchIndex(matched)
	if groups == nil || groups[0] != 0 {
		return nil
	}
	pairStart, pairEnd := -1, -1
	for _, index := range curlPairGroups {
		if groups[2*index] >= 0 {
			pairStart, pairEnd = groups[2*index], groups[2*index+1]
			break
		}
	}
	if pairStart < 0 {
		return nil
	}
	user, password, found := strings.Cut(matched[pairStart:pairEnd], ":")
	switch {
	case !found:
		return nil
	case password == "":
		// A token sent as the user name.
		if !secretShapedValue(keyMaterialName, user, groups[2*curlBarePairGroup] < 0) {
			return nil
		}
	case strings.ContainsAny(password[:1], notCredentialStarts):
		return nil
	case slices.Contains(placeholderPasswords, strings.ToLower(password)) || (isDigits(user) && isDigits(password)):
		return nil
	}
	if !curlCommandPattern.MatchString(commandBefore(input, offset)) {
		return nil
	}
	return []valueSpan{{offset + pairStart, offset + pairEnd}}
}

func isDigits(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return !isASCIIDigitRune(r) }) < 0
}

// commandBefore returns the text of the command that position offset belongs
// to, up to offset.
//
// The command starts at the start of its line. A line that the line before it
// continues with a trailing backslash is part of the same command. In text
// that carries encoded line ends, the two characters "\n" end a line too,
// unless a backslash before them marks a continuation.
//
// Inside that text the command starts after the last operator that begins
// another command (a pipe, a semicolon, &&, ||, or an & that sends the command
// before it to the background) and is not inside quotes. An operator inside
// quotes is part of an argument: -H "Accept: a; b".
func commandBefore(input string, offset int) string {
	floor := max(0, offset-maxCommandLookback)
	start := offset
	for start > floor {
		newline := strings.LastIndexByte(input[floor:start], '\n')
		if newline < 0 {
			start = floor
			break
		}
		newline += floor
		if !strings.HasSuffix(strings.TrimRight(input[floor:newline], " \t\r"), `\`) {
			start = newline + 1
			break
		}
		start = newline
	}
	command := input[start:offset]
	for cut := len(command); cut > 0; {
		cut = strings.LastIndex(command[:cut], encodedLineEnd)
		if cut < 0 {
			break
		}
		if cut == 0 || command[cut-1] != '\\' {
			command = command[cut+len(encodedLineEnd):]
			break
		}
	}
	return command[lastUnquotedOperator(command):]
}

// encodedLineEnd is a line end as a JSON string carries it.
const encodedLineEnd = `\n`

// lastUnquotedOperator returns the position after the last command operator
// in command that is outside quotes, or 0.
//
// A single "&" is an operator only when a space or the end of the text follows
// it. Without one it is part of a word: the "&" of a redirection (2>&1), or of
// a URL query that the command line leaves unquoted.
func lastUnquotedOperator(command string) int {
	after := 0
	var quote byte
	for i := 0; i < len(command); i++ {
		switch c := command[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '|' || c == ';':
			after = i + 1
		case c == '&' && (i+1 == len(command) || strings.IndexByte("& \t", command[i+1]) >= 0):
			after = i + 1
		}
	}
	return after
}

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

// jwkPrivateMemberPattern matches a private member and its base64url value.
// The member name is a whole word, with double quotes, escaped quotes, single
// quotes or none, so JSON, a JSON string, a printed dictionary and YAML all
// match. In YAML inside a JSON string the name follows an encoded line end
// (see encodedBreakLetters); no member name starts with one of those letters. The name stays in the output. jwkPrivateMemberFilter keeps a match
// only inside a JSON Web Key.
var jwkPrivateMemberPattern = regexp.MustCompile(
	`((?:^|[\s{,"'\\])[` + encodedBreakLetters + `]?(?:` + strings.Join(jwkPrivateMembers, "|") + `)(?:\\*["'])?[ \t]*:[ \t]*(?:\\*["'])?)` + jwkValueBody)

// jwkValuePattern is a whole member value, for RedactJSON.
var jwkValuePattern = regexp.MustCompile(`^` + jwkValueBody + `$`)

// jwkKeyTypePattern is the key-type member in the same four spellings.
var jwkKeyTypePattern = regexp.MustCompile(`(?:^|[\s{,"'\\])[` + encodedBreakLetters + `]?` + jwkKeyTypeMember + `(?:\\*["'])?[ \t]*:`)

// jwkPrivateMemberFilter keeps a match that has a key-type member near it.
func jwkPrivateMemberFilter(matched, input string, offset int) bool {
	// The match is the character before the name, if any, then the letter of
	// an encoded line end, if any, then the name.
	name := 0
	if !isWordByte(matched[0]) {
		name = 1
	}
	if strings.IndexByte(encodedBreakLetters, matched[name]) >= 0 && !endsEncodedBreak(input, offset+name+1) {
		return false
	}
	start := max(0, offset-jwkContextWindow)
	end := min(len(input), offset+len(matched)+jwkContextWindow)
	return jwkKeyTypePattern.MatchString(input[start:end])
}

// isJWKPrivateMember reports whether RedactJSON replaces the value of key in
// an object that carries a key-type member.
func isJWKPrivateMember(key, value string) bool {
	return slices.Contains(jwkPrivateMembers, key) && jwkValuePattern.MatchString(value)
}

// headerValueKeys are the object keys whose string value RedactJSON reads as
// the value of that header. The rules for these headers need the header name
// in front of the value, and a decoded object holds the two apart.
//
// The list is closed. Not read as a header, and so left to the rules that
// need no header name: a value under "proxy-authorization", and a header
// whose value is a list of strings ({"Cookie": ["a=b"]}).
var headerValueKeys = []string{"authorization", "cookie", "set-cookie"}

// isHeaderValueKey reports whether key names one of headerValueKeys.
func isHeaderValueKey(key string) bool {
	return slices.Contains(headerValueKeys, strings.ToLower(key))
}
