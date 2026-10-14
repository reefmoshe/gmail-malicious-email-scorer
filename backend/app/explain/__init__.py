"""Explanation layer: runs strictly AFTER scoring and returns wording only.

explain() receives the finished engine result and returns an Explanation; it never
returns or modifies scores, verdicts or findings. It is called only by POST /explain,
i.e. when the user clicks "Explain with AI"; /analyze uses the template and never calls
a provider. The LLM path falls back to the deterministic template on any problem.
"""

from ..schemas import AnalyzeResponse, Explanation
from . import llm
from .template import template_explanation

AI_NOTICE = (
    "AI-written explanation of the rule-based result above. It does not change the verdict "
    "or score and may simplify details - see the findings below."
)


def explain(result: AnalyzeResponse) -> Explanation:
    if not llm.is_enabled():
        return template_explanation(result)
    # The LLM sees a copy: nothing it returns can reach the engine result.
    generated = llm.generate(result.model_copy(deep=True))
    if generated is None:
        return template_explanation(result)
    return Explanation(
        source="ai",
        summary=generated.summary,
        key_reasons=generated.key_reasons,
        recommendation=generated.recommendation,
        limitations=generated.limitations,
        notice=AI_NOTICE,
    )
