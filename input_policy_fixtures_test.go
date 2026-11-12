package redact

import (
	"fmt"
	"slices"

	"gopkg.in/yaml.v3"
)

type chunkCaseName string

const (
	chunkExactBoundary               chunkCaseName = "engine_chunk_exact_boundary"
	chunkCrossingLiteral             chunkCaseName = "engine_chunk_crossing_literal"
	chunkCrossingEmail               chunkCaseName = "engine_chunk_crossing_email"
	chunkAbsoluteOffsets             chunkCaseName = "chunk_offsets_are_absolute"
	chunkWholeInputFilter            chunkCaseName = "chunk_filterfn_sees_whole_input"
	chunkIdenticalOutput             chunkCaseName = "chunked_output_is_identical"
	chunkNoDuplicates                chunkCaseName = "chunk_no_duplicate_matches"
	chunkNonoverlappingSelection     chunkCaseName = "chunk_nonoverlapping_selection"
	chunkWordLineBoundaries          chunkCaseName = "chunk_word_and_line_boundaries"
	chunkTextAnchors                 chunkCaseName = "chunk_text_anchors"
	chunkUnicodeBoundaries           chunkCaseName = "chunk_unicode_boundaries"
	chunkUnfinishedPrefix            chunkCaseName = "chunk_unfinished_prefix_refused"
	chunkEmptyPattern                chunkCaseName = "chunk_empty_pattern_refused"
	chunkPendingLiteral              chunkCaseName = "chunk_pending_literal_at_window_edge"
	chunkRealWindowAnchors           chunkCaseName = "chunk_anchors_across_real_windows"
	chunkPreserves200MiB             chunkCaseName = "engine_preserves_matches_200_mib"
	chunkPreserves200MiB16MiBWindows chunkCaseName = "engine_preserves_matches_200_mib_16_mib_windows"
	chunkFullCatalogParity           chunkCaseName = "full_catalog_chunked_parity"
)

var requiredChunkCaseNames = []chunkCaseName{
	chunkExactBoundary,
	chunkCrossingLiteral,
	chunkCrossingEmail,
	chunkAbsoluteOffsets,
	chunkWholeInputFilter,
	chunkIdenticalOutput,
	chunkNoDuplicates,
	chunkNonoverlappingSelection,
	chunkWordLineBoundaries,
	chunkTextAnchors,
	chunkUnicodeBoundaries,
	chunkUnfinishedPrefix,
	chunkEmptyPattern,
	chunkPendingLiteral,
	chunkRealWindowAnchors,
	chunkPreserves200MiB,
	chunkPreserves200MiB16MiBWindows,
}

var AllChunkCaseNames = append(slices.Clone(requiredChunkCaseNames), chunkFullCatalogParity)

func NewChunkCaseName(raw string) (chunkCaseName, error) {
	return newFixtureEnum(raw, AllChunkCaseNames, "chunk case")
}

func (name *chunkCaseName) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := NewChunkCaseName(node.Value)
	if err != nil {
		return err
	}
	*name = parsed
	return nil
}

type policyCaseName string

const (
	policyZeroChunk             policyCaseName = "policy_rejects_zero_chunk"
	policyNegativeChunk         policyCaseName = "policy_rejects_negative_chunk"
	policyZeroCeiling           policyCaseName = "policy_rejects_zero_ceiling"
	policyNegativeCeiling       policyCaseName = "policy_rejects_negative_ceiling"
	policyChunkAboveCeiling     policyCaseName = "policy_rejects_chunk_above_ceiling"
	policyCeilingAtWASMLimit    policyCaseName = "policy_rejects_ceiling_at_wasm_limit"
	policyCeilingAboveWASMLimit policyCaseName = "policy_rejects_ceiling_above_wasm_limit"
	policyEqualChunkCeiling     policyCaseName = "policy_accepts_equal_chunk_ceiling"
	policyProductionCaps        policyCaseName = "policy_defaults_match_production_caps"
	policyRefusesTwoGiB         policyCaseName = "engine_refuses_two_gib"
	policyRefusesExactCeiling   policyCaseName = "engine_refuses_exact_ceiling"
	policyAcceptsBelowCeiling   policyCaseName = "engine_accepts_below_ceiling"
)

var AllPolicyCaseNames = []policyCaseName{
	policyZeroChunk,
	policyNegativeChunk,
	policyZeroCeiling,
	policyNegativeCeiling,
	policyChunkAboveCeiling,
	policyCeilingAtWASMLimit,
	policyCeilingAboveWASMLimit,
	policyEqualChunkCeiling,
	policyProductionCaps,
	policyRefusesTwoGiB,
	policyRefusesExactCeiling,
	policyAcceptsBelowCeiling,
}

func NewPolicyCaseName(raw string) (policyCaseName, error) {
	return newFixtureEnum(raw, AllPolicyCaseNames, "policy case")
}

func (name *policyCaseName) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := NewPolicyCaseName(node.Value)
	if err != nil {
		return err
	}
	*name = parsed
	return nil
}

type refusalCaseName string

const (
	refusalCheckedDetect      refusalCaseName = "checked_detect_refuses_before_engine"
	refusalCheckedText        refusalCaseName = "checked_text_refuses_before_engine"
	refusalCheckedJSON        refusalCaseName = "checked_json_refuses_nested_leaf"
	refusalJSONL              refusalCaseName = "jsonl_refusal_preserves_original_with_error"
	refusalCheckedDocument    refusalCaseName = "document_refusal_has_error"
	refusalLegacyDetect       refusalCaseName = "legacy_detect_masks_refusal"
	refusalLegacyText         refusalCaseName = "legacy_text_masks_refusal"
	refusalLegacyJSON         refusalCaseName = "legacy_json_masks_refusal"
	refusalLegacyDocument     refusalCaseName = "legacy_document_masks_refusal"
	refusalLegacySuppliedSpan refusalCaseName = "legacy_redact_masks_oversized_supplied_span"
	refusalTitleGenerate      refusalCaseName = "title_generate_refuses_before_engine"
	refusalTitleSanitize      refusalCaseName = "title_sanitize_refuses_before_engine"
)

var AllRefusalCaseNames = []refusalCaseName{
	refusalCheckedDetect,
	refusalCheckedText,
	refusalCheckedJSON,
	refusalJSONL,
	refusalCheckedDocument,
	refusalLegacyDetect,
	refusalLegacyText,
	refusalLegacyJSON,
	refusalLegacyDocument,
	refusalLegacySuppliedSpan,
	refusalTitleGenerate,
	refusalTitleSanitize,
}

func NewRefusalCaseName(raw string) (refusalCaseName, error) {
	return newFixtureEnum(raw, AllRefusalCaseNames, "refusal case")
}

func (name *refusalCaseName) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := NewRefusalCaseName(node.Value)
	if err != nil {
		return err
	}
	*name = parsed
	return nil
}

type refusalOperation string

const (
	refusalOperationCheckedDetect   refusalOperation = "detect_checked"
	refusalOperationCheckedText     refusalOperation = "text_checked"
	refusalOperationCheckedJSON     refusalOperation = "json_checked"
	refusalOperationJSONL           refusalOperation = "jsonl"
	refusalOperationCheckedDocument refusalOperation = "document_checked"
	refusalOperationDetect          refusalOperation = "detect"
	refusalOperationText            refusalOperation = "text"
	refusalOperationJSON            refusalOperation = "json"
	refusalOperationDocument        refusalOperation = "document"
	refusalOperationRedact          refusalOperation = "redact"
	refusalOperationTitleGenerate   refusalOperation = "title_generate"
	refusalOperationTitleSanitize   refusalOperation = "title_sanitize"
)

var AllRefusalOperations = []refusalOperation{
	refusalOperationCheckedDetect,
	refusalOperationCheckedText,
	refusalOperationCheckedJSON,
	refusalOperationJSONL,
	refusalOperationCheckedDocument,
	refusalOperationDetect,
	refusalOperationText,
	refusalOperationJSON,
	refusalOperationDocument,
	refusalOperationRedact,
	refusalOperationTitleGenerate,
	refusalOperationTitleSanitize,
}

func NewRefusalOperation(raw string) (refusalOperation, error) {
	return newFixtureEnum(raw, AllRefusalOperations, "refusal operation")
}

func (operation *refusalOperation) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := NewRefusalOperation(node.Value)
	if err != nil {
		return err
	}
	*operation = parsed
	return nil
}

func newFixtureEnum[T ~string](raw string, known []T, kind string) (T, error) {
	for _, value := range known {
		if string(value) == raw {
			return value, nil
		}
	}
	return "", fmt.Errorf("unknown %s %q in testdata/engine_chunking.yaml; use a reviewed typed constant", kind, raw)
}

func validateTypedChunkManifest[T ~string](section string, required, manifest, actual []T) error {
	stringsOf := func(names []T) []string {
		result := make([]string, len(names))
		for i, name := range names {
			result[i] = string(name)
		}
		return result
	}
	const path = "testdata/engine_chunking.yaml"
	if err := requireFixtureNames(path, section, stringsOf(required), stringsOf(manifest)); err != nil {
		return err
	}
	return requireFixtureNames(path, section, stringsOf(required), stringsOf(actual))
}
