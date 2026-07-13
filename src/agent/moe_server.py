#!/usr/bin/env python3
"""
NATO Smart City IoT — Hybrid Mixture of Experts (HMoE) Server

This server acts as an OpenAI-compatible API endpoint.
It loads a single base model in 4-bit (via bitsandbytes) and dynamically swaps
LoRA adapters (experts) using PEFT based on the requested model name or by
automatically analyzing the system prompt.

Usage:
    python3 src/agent/moe_server.py --base-model Qwen/Qwen2.5-0.5B-Instruct --adapters-dir output/adapters/lance-qlora_moe
"""

import os
import re
import json
import uuid
import time
import argparse
import logging
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("moe-server")

app = FastAPI(title="LANCE HMoE Server", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- Global State ---
_MODEL = None
_TOKENIZER = None
_ADAPTERS = []

# --- API Models ---
class Message(BaseModel):
    role: str
    content: str | List[Dict[str, Any]] = ""
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[Message]
    tools: Optional[List[Dict[str, Any]]] = None
    max_tokens: Optional[int] = 4096
    temperature: Optional[float] = 0.0

# --- Router Logic ---
def _route_expert(messages: List[Message]) -> str:
    """Determine the expert based on exact LANCE system prompt roles."""
    sys_prompt = next((m.content for m in messages if m.role == "system"), "")
    if not isinstance(sys_prompt, str):
        sys_prompt = json.dumps(sys_prompt)
    sys_prompt = sys_prompt.lower()
    
    # Check for exact roles defined in the first lines of LANCE prompts
    if "topology analyst" in sys_prompt or "report writer" in sys_prompt:
        return "secretary"
    elif "reconnaissance and network scanning" in sys_prompt:
        return "recon"
    elif "vulnerability analyst" in sys_prompt:
        return "vuln"
    elif "exploit verification agent" in sys_prompt or "offensive security agent" in sys_prompt:
        return "exploit"
    
    # Fallback to base model if no clear match
    return "base"

# --- Qwen Tool Call Parser ---
def _parse_qwen_tool_calls(text: str) -> tuple[str, list[dict]]:
    """Parse Qwen's <tool_call> tags into OpenAI tool_calls structure."""
    content_parts = []
    tool_calls = []
    
    # Qwen tool call format:
    # <tool_call>
    # {"name": "func_name", "arguments": {"arg1": "val1"}}
    # </tool_call>
    
    pattern = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.DOTALL)
    
    last_idx = 0
    for match in pattern.finditer(text):
        if match.start() > last_idx:
            content_parts.append(text[last_idx:match.start()].strip())
        
        try:
            call_data = json.loads(match.group(1))
            tool_calls.append({
                "id": f"call_{uuid.uuid4().hex[:8]}",
                "type": "function",
                "function": {
                    "name": call_data.get("name"),
                    # OpenAI expects arguments as stringified JSON
                    "arguments": json.dumps(call_data.get("arguments", {}))
                }
            })
        except Exception as e:
            log.error(f"Failed to parse tool call: {e}")
            
        last_idx = match.end()
        
    if last_idx < len(text):
        content_parts.append(text[last_idx:].strip())
        
    return "\n".join(content_parts).strip(), tool_calls

# --- Endpoints ---
@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest):
    global _MODEL, _TOKENIZER, _ADAPTERS
    if not _MODEL:
        raise HTTPException(status_code=503, detail="Model not initialized")
        
    # Determine the expert to use
    target_expert = "base"
    if req.model == "lance-moe":
        target_expert = _route_expert(req.messages)
        log.info(f"[ROUTER] Automatically routed to expert: {target_expert}")
    elif req.model.startswith("expert-"):
        target_expert = req.model.replace("expert-", "")
        log.info(f"[ROUTER] Manual standalone expert requested: {target_expert}")
        
    # Swap adapter
    if target_expert != "base":
        if target_expert not in _ADAPTERS:
            log.warning(f"Expert {target_expert} not found in loaded adapters. Falling back to base model.")
            _MODEL.set_adapter("default") # PEFT default is base
        else:
            _MODEL.set_adapter(target_expert)
            log.info(f"Active Adapter: {target_expert}")
    else:
        _MODEL.set_adapter("default")
        log.info("Active Adapter: BASE")

    # Format messages for the tokenizer
    hf_messages = []
    for m in req.messages:
        content = m.content if isinstance(m.content, str) else json.dumps(m.content)
        hf_messages.append({"role": m.role, "content": content})
        
    # Render prompt with chat template (handling tools if supported)
    try:
        # Qwen2.5-Instruct supports tools in apply_chat_template
        prompt = _TOKENIZER.apply_chat_template(
            hf_messages,
            tools=req.tools,
            tokenize=False,
            add_generation_prompt=True
        )
    except Exception as e:
        log.warning(f"Tokenizer tool formatting failed, falling back to basic template: {e}")
        prompt = _TOKENIZER.apply_chat_template(hf_messages, tokenize=False, add_generation_prompt=True)
        
    # Generate
    inputs = _TOKENIZER(prompt, return_tensors="pt").to(_MODEL.device)
    
    t0 = time.time()
    with torch.no_grad():
        outputs = _MODEL.generate(
            **inputs,
            max_new_tokens=req.max_tokens,
            temperature=req.temperature if req.temperature > 0 else 0.01,
            do_sample=req.temperature > 0,
            pad_token_id=_TOKENIZER.eos_token_id
        )
    t1 = time.time()
    
    # Extract only the newly generated tokens
    generated_ids = outputs[0][inputs.input_ids.shape[-1]:]
    response_text = _TOKENIZER.decode(generated_ids, skip_special_tokens=True)
    
    # Parse potential tool calls
    content, tool_calls = _parse_qwen_tool_calls(response_text)
    
    # Format response for OpenAI compatibility
    res_msg = {"role": "assistant"}
    if content:
        res_msg["content"] = content
    if tool_calls:
        res_msg["tool_calls"] = tool_calls
        
    input_tokens = inputs.input_ids.shape[-1]
    output_tokens = len(generated_ids)
    
    log.info(f"Generated {output_tokens} tokens in {t1-t0:.2f}s ({output_tokens/(t1-t0):.1f} t/s)")
    
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": res_msg,
            "finish_reason": "tool_calls" if tool_calls else "stop"
        }],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens
        }
    }


def load_models(base_model_path: str, adapters_dir: str):
    global _MODEL, _TOKENIZER, _ADAPTERS
    log.info(f"Loading base model in 4-bit: {base_model_path}")
    
    quantization_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16
    )
    
    _TOKENIZER = AutoTokenizer.from_pretrained(base_model_path)
    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_path,
        quantization_config=quantization_config,
        device_map="auto",
        torch_dtype=torch.bfloat16,
    )
    
    _MODEL = base_model
    
    if os.path.isdir(adapters_dir):
        # Find checkpoint directories inside each expert folder
        for expert_name in ["recon", "vuln", "exploit", "secretary"]:
            expert_dir = os.path.join(adapters_dir, expert_name)
            if not os.path.exists(expert_dir):
                log.warning(f"Expert dir not found: {expert_dir}")
                continue
                
            # Find highest checkpoint
            checkpoints = [d for d in os.listdir(expert_dir) if d.startswith("checkpoint-")]
            if not checkpoints:
                log.warning(f"No checkpoints found in {expert_dir}")
                continue
                
            best_ckpt = sorted(checkpoints, key=lambda x: int(x.split("-")[1]))[-1]
            adapter_path = os.path.join(expert_dir, best_ckpt)
            
            log.info(f"Loading adapter [{expert_name}] from {adapter_path}")
            # If it's the first adapter, PeftModel wraps the base model
            if not isinstance(_MODEL, PeftModel):
                _MODEL = PeftModel.from_pretrained(base_model, adapter_path, adapter_name=expert_name)
            else:
                _MODEL.load_adapter(adapter_path, adapter_name=expert_name)
            _ADAPTERS.append(expert_name)
            
    log.info(f"HMoE initialization complete. Loaded adapters: {_ADAPTERS}")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-model", default="Qwen/Qwen2.5-0.5B-Instruct", help="Path or HF hub ID for the base model")
    parser.add_argument("--adapters-dir", default="output/adapters/lance-qlora_moe", help="Directory containing the expert adapters")
    parser.add_argument("--port", type=int, default=8001, help="Port to run the API server on")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()
    
    # Load model synchronously before starting server
    load_models(args.base_model, args.adapters_dir)
    
    uvicorn.run(app, host=args.host, port=args.port)
