"""Local demo API; uses a deterministic mock instead of calling a hosted model."""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from llm_guard import Guard

app = FastAPI(title="llm-guard demo", description="Offline LLM boundary scanning example")
guard = Guard()


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10_000)


@app.post("/chat")
def chat(request: ChatRequest) -> dict[str, object]:
    incoming = guard.check_input(request.message)
    if incoming.is_blocked:
        raise HTTPException(status_code=400, detail={"error": "Request blocked", **incoming.to_dict()})

    # Replace this deterministic example with an explicitly configured model provider.
    response = f"Demo received {len(request.message)} characters. No model was called."
    outgoing = guard.check_output(response)
    if outgoing.is_blocked:
        raise HTTPException(status_code=502, detail={"error": "Response blocked", **outgoing.to_dict()})
    return {"response": response, "input_scan": incoming.to_dict(), "output_scan": outgoing.to_dict()}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "llm-guard-demo"}
