// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"regexp"

	"golang.org/x/text/unicode/norm"
)

// templateTokenRe finds chat template control tokens, in any case.
// The families are: `<|name|>` (ChatML, Llama 3, Phi, and DeepSeek
// after NFKC folds its full-width bar), `[INST]` and `[/INST]`,
// `<<SYS>>` and `<</SYS>>`, `<start_of_turn>` and `<end_of_turn>`,
// the Mistral tokens `[SYSTEM_PROMPT]`, `[TOOL_CALLS]` and
// `[AVAILABLE_TOOLS]`, the Llama/Mistral sentence tokens `<s>` and
// `</s>`, and a `Human:` or `Assistant:` turn prefix, but only at the
// start of a line: mid-line it is plain text a sender can write about
// a person, not a turn marker a runtime parses.
//
// The pattern also finds these families. Each item names the runtime
// or the format that reads the token:
//
//   - `<tool_call>` and `<tool_response>`, open and close: Qwen and
//     Hermes.
//   - `<function_calls>` and `<function_results>`, open and close, and
//     `<invoke`: Anthropic tool use in text form.
//   - `[TOOL_RESULTS]` and `[/TOOL_RESULTS]`: Mistral.
//   - `<system>` and `</system>`: chat transcripts.
//   - A `System:` turn prefix at the start of a line: chat transcripts.
//   - `### Instruction:` and `### Response:` at the start of a line:
//     Alpaca.
//
// arch: D4.1, DH2.4
var templateTokenRe = regexp.MustCompile(`(?im)` +
	`<\|[^|\s<>]{1,64}\|>` +
	`|\[/?INST\]` +
	`|<</?SYS>>` +
	`|<(?:start|end)_of_turn>` +
	`|\[SYSTEM_PROMPT\]` +
	`|\[TOOL_CALLS\]` +
	`|\[AVAILABLE_TOOLS\]` +
	`|</?s>` +
	`|</?tool_call>` +
	`|</?tool_response>` +
	`|</?function_calls>` +
	`|<invoke\b` +
	`|</?function_results>` +
	`|\[/?TOOL_RESULTS\]` +
	`|</?system>` +
	`|^(?:Human|Assistant|System):` +
	`|^###[ \t]*(?:Instruction|Response):`)

// escapeTemplateTokens replaces each chat template token in s with a
// form that does not match what a model runtime looks for, but that a
// human can still read. A token that starts with an ASCII bracket
// byte (`<` or `[`) loses that bracket to U+27E6, the same substitute
// that escapeMarkers uses. A word token (`Human:`, `Assistant:`) has
// no bracket, so U+27E6 goes in front of it instead; the word stays
// whole and readable.
//
// arch: D4.1
func escapeTemplateTokens(s string) string {
	return templateTokenRe.ReplaceAllStringFunc(s, func(m string) string {
		if m[0] == '<' || m[0] == '[' {
			return "⟦" + m[1:]
		}
		return "⟦" + m
	})
}

// Sanitize makes sender text safe to put inside a fence. The steps
// are, in this order:
//
//  1. NFKC. Full-width and other compatibility forms of a marker or a
//     template token become their plain ASCII form, so the next steps
//     find them.
//  2. StripInvisible. This runs after NFKC, so the output has no
//     hidden character, also when NFKC makes one.
//  3. escapeMarkers. A forged fence marker loses its bracket.
//  4. escapeTemplateTokens. A chat template token loses its bracket.
//
// Fence calls Sanitize. A caller that fences text must use Fence.
//
// arch: D4.1, §3.15, G2, G4
func Sanitize(s string) string {
	s = norm.NFKC.String(s)
	s, _ = StripInvisible(s)
	s = escapeMarkers(s)
	return escapeTemplateTokens(s)
}

// CleanServerName makes a folder name or a label word safe to show
// outside a fence. The marker strip comes first, because a field
// outside a fence must not hold the bare word UNTRUSTED_, and Sanitize
// keeps that word when it escapes a marker. Sanitize runs NFKC, so a
// full-width name comes back in its plain form, and a later call with
// that name can fail. The owner accepted this.
//
// arch: DH2.5
func CleanServerName(s string) string {
	return Sanitize(StripFenceMarkers(s))
}
