from functools import lru_cache
from agno.models.google import Gemini
from agno.agent import Agent
from .config import settings
from .agents.expert_agent import build_expert_agent

@lru_cache
def get_llm_model():
    return Gemini(id="gemini-2.5-flash")

@lru_cache
def get_expert_agent() -> Agent:
    return build_expert_agent(get_llm_model())
