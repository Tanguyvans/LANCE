import json

filepath = 'data/raw_traces/synth_trace_1.jsonl'

with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}\n")

for i, line in enumerate(lines):
    stripped = line.strip()
    if not stripped:
        print(f"Line {i+1}: EMPTY")
        continue
    try:
        json.loads(stripped)
        # Valid - check structure
        data = json.loads(stripped)
        tool = data.get('tool', 'MISSING')
        has_args = 'args' in data
        has_result = 'result' in data
        if tool == 'MISSING' or not has_args or not has_result:
            print(f"Line {i+1}: VALID JSON but MISSING FIELDS (tool={tool}, args={has_args}, result={has_result})")
        else:
            pass  # valid, skip
    except json.JSONDecodeError as e:
        print(f"Line {i+1}: INVALID JSON -> {e}")
        # Show the context around the error
        col = e.colno
        start = max(0, col - 60)
        end = min(len(stripped), col + 60)
        print(f"  Context: ...{repr(stripped[start:end])}...")
        print()

print("\nDone.")
