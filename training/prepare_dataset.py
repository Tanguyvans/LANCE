import json
import os
import argparse

def format_lance_trace(trace_file: str) -> dict:
    """
    Reads a LANCE tool_calls.jsonl trace and formats it into a conversation suitable for fine-tuning.
    """
    messages = []
    
    system_prompt = "You are LANCE, an autonomous LLM Agent for Network Compromise Evaluation. Your goal is to identify and exploit vulnerabilities using the tools provided."
    messages.append({"role": "system", "content": system_prompt})
    
    # Initial prompt to kick off the interaction
    messages.append({"role": "user", "content": "Commence the network compromise evaluation."})
    
    with open(trace_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                # The assistant's action (the tool call it generated)
                action = {
                    "tool": data.get("tool"),
                    "args": data.get("args", {})
                }
                messages.append({"role": "assistant", "content": json.dumps(action, ensure_ascii=False)})
                
                # The observation/result from the environment is fed back as the next user message
                result = data.get("result", "")
                messages.append({"role": "user", "content": str(result)})
                
            except json.JSONDecodeError:
                print(f"Warning: Could not parse line in {trace_file}")
                continue
                
    return {"messages": messages}

def main(input_dir: str, output_file: str):
    """
    Convert a directory of traces into a JSONL dataset for QLoRA fine-tuning.
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    processed_count = 0
    with open(output_file, 'a', encoding='utf-8') as out_f:
        for root, _, files in os.walk(input_dir):
            for file in files:
                # Assuming the trace files are named tool_calls.jsonl or similar
                if file.endswith(".jsonl"):
                    trace_path = os.path.join(root, file)
                    try:
                        formatted_trace = format_lance_trace(trace_path)
                        if len(formatted_trace["messages"]) > 2: # More than just system + init
                            out_f.write(json.dumps(formatted_trace, ensure_ascii=False) + "\n")
                            processed_count += 1
                    except Exception as e:
                        print(f"Failed to process {trace_path}: {e}")
                        
    print(f"Successfully processed {processed_count} traces and saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_dir", type=str, default="data/raw_traces", help="Directory containing raw JSONL traces")
    parser.add_argument("--output_file", type=str, default="data/finetuning/dataset.jsonl", help="Output JSONL dataset path")
    args = parser.parse_args()
    
    main(args.input_dir, args.output_file)
