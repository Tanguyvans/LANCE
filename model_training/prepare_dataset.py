import json
import os
import argparse
import re

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

def format_txt_trace(trace_file: str) -> list:
    """
    Reads an AI-generated synthetic trace in custom <TRACE> XML-like format
    and returns a list of formatted conversations.
    """
    system_prompt = "You are LANCE, an autonomous LLM Agent for Network Compromise Evaluation. Your goal is to identify and exploit vulnerabilities using the tools provided."
    
    with open(trace_file, 'r', encoding='utf-8') as f:
        content = f.read()
        
    traces = re.findall(r'<TRACE>(.*?)</TRACE>', content, re.DOTALL)
    formatted_traces = []
    
    for trace in traces:
        messages = []
        messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": "Commence the network compromise evaluation."})
        
        steps = re.findall(r'<STEP>(.*?)</STEP>', trace, re.DOTALL)
        for step in steps:
            tool_match = re.search(r'<TOOL>(.*?)</TOOL>', step, re.DOTALL)
            args_match = re.search(r'<ARGS>(.*?)</ARGS>', step, re.DOTALL)
            result_match = re.search(r'<RESULT>(.*?)</RESULT>', step, re.DOTALL)
            
            if tool_match and args_match and result_match:
                tool = tool_match.group(1).strip()
                args_str = args_match.group(1).strip()
                result = result_match.group(1).strip()
                
                try:
                    args = json.loads(args_str)
                except:
                    args = {}
                
                action = {"tool": tool, "args": args}
                messages.append({"role": "assistant", "content": json.dumps(action, ensure_ascii=False)})
                messages.append({"role": "user", "content": result})
                
        if len(messages) > 2:
            formatted_traces.append({"messages": messages})
            
    return formatted_traces

def main(input_dir: str, output_file: str):
    """
    Convert a directory of traces into a JSONL dataset for QLoRA fine-tuning.
    Handles both original .jsonl files and synthetic .txt files.
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    processed_count = 0
    with open(output_file, 'a', encoding='utf-8') as out_f:
        for root, _, files in os.walk(input_dir):
            for file in files:
                filepath = os.path.join(root, file)
                
                if file.endswith(".jsonl"):
                    try:
                        formatted_trace = format_lance_trace(filepath)
                        if len(formatted_trace["messages"]) > 2:
                            out_f.write(json.dumps(formatted_trace, ensure_ascii=False) + "\n")
                            processed_count += 1
                    except Exception as e:
                        print(f"Failed to process JSONL {filepath}: {e}")
                        
                elif file.endswith(".txt"):
                    try:
                        formatted_traces = format_txt_trace(filepath)
                        for trace in formatted_traces:
                            out_f.write(json.dumps(trace, ensure_ascii=False) + "\n")
                            processed_count += 1
                    except Exception as e:
                        print(f"Failed to process TXT {filepath}: {e}")
                        
    print(f"Successfully processed {processed_count} traces and saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_dir", type=str, default="data/raw_traces", help="Directory containing raw traces (.jsonl or .txt)")
    parser.add_argument("--output_file", type=str, default="data/finetuning/dataset.jsonl", help="Output JSONL dataset path")
    args = parser.parse_args()
    
    main(args.input_dir, args.output_file)
