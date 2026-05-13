"""
@file test_scoring_logic.py
@brief Unit tests for the objective scoring heuristics in app.services.
@details Tests _meaningful_words, _objective_is_achieved, and
         _find_new_objective_achievement without any DB interaction.
"""

import pytest

from app.services import (
    _meaningful_words,
    _objective_is_achieved,
    _find_new_objective_achievement,
)

pytestmark = pytest.mark.unit


# ── _meaningful_words ─────────────────────────────────────────────────────

class TestMeaningfulWords:
    """Validate text normalization and stop-word filtering."""

    def test_lowercases_and_strips_punctuation(self):
        """Output words must be lowercase with no punctuation."""
        words = _meaningful_words("Hello, WORLD! Foo-bar.")

        assert all(w.isalnum() for w in words)
        assert all(w == w.lower() for w in words)

    def test_removes_stop_words(self):
        """Common stop words must be excluded from the result set."""
        words = _meaningful_words("the quick brown fox is a fast animal")

        assert "the" not in words
        assert "is" not in words
        assert "a" not in words

    def test_removes_short_words(self):
        """Words with 2 or fewer characters must be excluded."""
        words = _meaningful_words("I am at it on go")

        assert "am" not in words
        assert "at" not in words
        assert "it" not in words

    def test_empty_input(self):
        """Empty or None input must return an empty set."""
        assert _meaningful_words("") == set()
        assert _meaningful_words(None) == set()

    def test_returns_set(self):
        """Return type must be a set."""
        result = _meaningful_words("photosynthesis process")

        assert isinstance(result, set)


# ── _objective_is_achieved ────────────────────────────────────────────────

class TestObjectiveIsAchieved:
    """Validate majority-match threshold logic."""

    def test_empty_objective_words_returns_false(self):
        """An objective with no meaningful words cannot be achieved."""
        assert _objective_is_achieved(set(), ["word"]) is False

    def test_single_word_objective_needs_exact_match(self):
        """A single-word objective requires that word in matched_words."""
        assert _objective_is_achieved({"photosynthesis"}, ["photosynthesis"]) is True

    def test_single_word_objective_no_match(self):
        """No match for single-word objective returns False."""
        assert _objective_is_achieved({"photosynthesis"}, []) is False

    def test_two_word_objective_needs_both(self):
        """A two-word objective requires both words matched."""
        words = {"cellular", "respiration"}

        assert _objective_is_achieved(words, ["cellular", "respiration"]) is True
        assert _objective_is_achieved(words, ["cellular"]) is False

    def test_multi_word_objective_needs_majority(self):
        """A 5-word objective needs at least ceil(5*3/5) = 3 matches (floor-adjusted)."""
        words = {"aaa", "bbb", "ccc", "ddd", "eee"}
        # With 5 words: required = max(2, (5*3+4)//5) = max(2, 3) = 3
        three_matches = ["aaa", "bbb", "ccc"]
        two_matches = ["aaa", "bbb"]

        assert _objective_is_achieved(words, three_matches) is True
        assert _objective_is_achieved(words, two_matches) is False


# ── _find_new_objective_achievement ───────────────────────────────────────

class TestFindNewObjectiveAchievement:
    """Validate the first-unearned-match selection logic."""

    def test_achieves_first_unearned_objective(self):
        """Should return the first objective whose words match the answer."""
        objectives = [
            "cellular respiration energy",
            "photosynthesis light reactions",
        ]
        answer = "Cellular respiration produces energy in mitochondria"

        result = _find_new_objective_achievement(
            objectives=objectives,
            answer=answer,
            earned_indexes=set(),
        )

        assert result is not None
        obj_idx, obj_text, matched = result
        assert obj_idx == 0

    def test_skips_already_earned_objective(self):
        """An already-earned objective must be skipped even if the answer matches it."""
        objectives = [
            "cellular respiration energy",
            "photosynthesis light reactions",
        ]
        answer = "Cellular respiration produces energy in mitochondria"

        result = _find_new_objective_achievement(
            objectives=objectives,
            answer=answer,
            earned_indexes={0},
        )

        # Objective 0 is earned, and the answer does not match objective 1.
        assert result is None

    def test_returns_none_when_nothing_matches(self):
        """If the answer does not match any objective, return None."""
        objectives = ["quantum entanglement superposition"]
        answer = "The weather is sunny today"

        result = _find_new_objective_achievement(
            objectives=objectives,
            answer=answer,
            earned_indexes=set(),
        )

        assert result is None

    def test_returns_none_when_all_earned(self):
        """If all objectives are earned, return None regardless of answer content."""
        objectives = ["cellular respiration energy"]
        answer = "cellular respiration energy production"

        result = _find_new_objective_achievement(
            objectives=objectives,
            answer=answer,
            earned_indexes={0},
        )

        assert result is None

    def test_matched_words_are_sorted(self):
        """The matched_words list must be sorted alphabetically."""
        objectives = ["zebra animal biology"]
        answer = "biology of the zebra animal"

        result = _find_new_objective_achievement(
            objectives=objectives,
            answer=answer,
            earned_indexes=set(),
        )

        assert result is not None
        _, _, matched = result
        assert matched == sorted(matched)
