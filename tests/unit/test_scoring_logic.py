"""
@file test_scoring_logic.py
@brief Unit tests for the objective scoring heuristics in app.services.
@details Tests _meaningful_words, _objective_is_achieved, and
         _find_new_objective_achievement without any DB interaction.

         _find_new_objective_achievement is an async function that calls
         DeepSeek API first, then falls back to keyword matching. Tests
         mock call_deepseek_api to simulate API failure so the keyword
         matching fallback path is exercised deterministically.
"""

import pytest
from unittest.mock import AsyncMock, patch

from app import services
from app.services import (
    _meaningful_words,
    _objective_is_achieved,
    _find_new_objective_achievement,
)

pytestmark = pytest.mark.unit


# -- _meaningful_words --------------------------------------------------------

class TestMeaningfulWords:
    """Validate text normalization and stop-word filtering."""

    def test_lowercases_and_strips_punctuation(self):
        words = _meaningful_words("Hello, WORLD! Foo-bar.")
        assert all(w.isalnum() for w in words)
        assert all(w == w.lower() for w in words)

    def test_removes_stop_words(self):
        words = _meaningful_words("the quick brown fox is a fast animal")
        assert "the" not in words
        assert "is" not in words
        assert "a" not in words

    def test_removes_short_words(self):
        words = _meaningful_words("I am at it on go")
        assert "am" not in words
        assert "at" not in words
        assert "it" not in words

    def test_empty_input(self):
        assert _meaningful_words("") == set()
        assert _meaningful_words(None) == set()

    def test_returns_set(self):
        result = _meaningful_words("photosynthesis process")
        assert isinstance(result, set)


# -- _objective_is_achieved ---------------------------------------------------

class TestObjectiveIsAchieved:
    """Validate majority-match threshold logic."""

    def test_empty_objective_words_returns_false(self):
        assert _objective_is_achieved(set(), ["word"]) is False

    def test_single_word_objective_needs_exact_match(self):
        assert _objective_is_achieved({"photosynthesis"}, ["photosynthesis"]) is True

    def test_single_word_objective_no_match(self):
        assert _objective_is_achieved({"photosynthesis"}, []) is False

    def test_two_word_objective_needs_both(self):
        words = {"cellular", "respiration"}
        assert _objective_is_achieved(words, ["cellular", "respiration"]) is True
        assert _objective_is_achieved(words, ["cellular"]) is False

    def test_multi_word_objective_needs_majority(self):
        words = {"aaa", "bbb", "ccc", "ddd", "eee"}
        assert _objective_is_achieved(words, ["aaa", "bbb", "ccc"]) is True
        assert _objective_is_achieved(words, ["aaa", "bbb"]) is False


# -- _find_new_objective_achievement ------------------------------------------

class TestFindNewObjectiveAchievement:
    """
    Validate the unearned-objective selection logic.

    _find_new_objective_achievement is async and calls call_deepseek_api
    internally. We patch that to None (API failure) so the keyword-matching
    fallback executes deterministically.
    """

    async def test_achieves_first_unearned_objective(self):
        objectives = [
            "cellular respiration energy",
            "photosynthesis light reactions",
        ]
        answer = "Cellular respiration produces energy in mitochondria"

        with patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=None):
            result = await _find_new_objective_achievement(
                objectives=objectives,
                answer=answer,
                earned_indexes=set(),
            )

        assert result is not None
        obj_idx, obj_text, matched = result
        assert obj_idx == 0

    async def test_skips_already_earned_objective(self):
        objectives = [
            "cellular respiration energy",
            "photosynthesis light reactions",
        ]
        answer = "Cellular respiration produces energy in mitochondria"

        with patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=None):
            result = await _find_new_objective_achievement(
                objectives=objectives,
                answer=answer,
                earned_indexes={0},
            )

        assert result is None

    async def test_returns_none_when_nothing_matches(self):
        objectives = ["quantum entanglement superposition"]
        answer = "The weather is sunny today"

        with patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=None):
            result = await _find_new_objective_achievement(
                objectives=objectives,
                answer=answer,
                earned_indexes=set(),
            )

        assert result is None

    async def test_returns_none_when_all_earned(self):
        objectives = ["cellular respiration energy"]
        answer = "cellular respiration energy production"

        with patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=None):
            result = await _find_new_objective_achievement(
                objectives=objectives,
                answer=answer,
                earned_indexes={0},
            )

        assert result is None

    async def test_matched_words_are_sorted(self):
        objectives = ["zebra animal biology"]
        answer = "biology of the zebra animal"

        with patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=None):
            result = await _find_new_objective_achievement(
                objectives=objectives,
                answer=answer,
                earned_indexes=set(),
            )

        assert result is not None
        _, _, matched = result
        assert matched == sorted(matched)

    async def test_uses_deepseek_result_when_api_succeeds(self):
        objectives = [
            "cellular respiration energy",
            "photosynthesis light reactions",
        ]
        answer = "Plants use sunlight"
        api_response = {"achieved_index": 1, "matched_words": ["light", "reactions"]}

        with patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=api_response):
            result = await _find_new_objective_achievement(
                objectives=objectives,
                answer=answer,
                earned_indexes=set(),
            )

        assert result is not None
        obj_idx, obj_text, matched = result
        assert obj_idx == 1
        assert matched == ["light", "reactions"]

    async def test_ignores_deepseek_result_for_earned_objective(self):
        objectives = ["cellular respiration energy"]
        answer = "cellular respiration produces energy"
        api_response = {"achieved_index": 0, "matched_words": ["cellular", "energy"]}

        with patch.object(services, "call_deepseek_api", new_callable=AsyncMock, return_value=api_response):
            result = await _find_new_objective_achievement(
                objectives=objectives,
                answer=answer,
                earned_indexes={0},
            )

        assert result is None
