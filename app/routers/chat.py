from fastapi import APIRouter, Depends
from pydantic import BaseModel
from ..deps import get_expert_agent

router = APIRouter(prefix="/chat", tags=["chat"])

class ChatRequest(BaseModel):
    message: str

@router.post("/expert")
def chat_expert(payload: ChatRequest, agent = Depends(get_expert_agent)):
    response = agent.run(payload.message)
    return {"reply": str(response.output_text)}
