import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

base_model_id = "Qwen/Qwen2.5-0.5B-Instruct"
adapter_dir = "output/adapters/lance-qlora_moe/recon"

print(f"Loading {base_model_id} + adapters from {adapter_dir}...")

tokenizer = AutoTokenizer.from_pretrained(base_model_id)
base_model = AutoModelForCausalLM.from_pretrained(
    base_model_id,
    torch_dtype=torch.bfloat16,
    device_map="auto"
)
model = PeftModel.from_pretrained(base_model, adapter_dir)
model.eval()

# Test Scenario: Demander à l'expert Recon de scanner une IP
messages = [
    {"role": "system", "content": "You are a network reconnaissance agent specialized in IoT security.\nYour mission is to discover every device on the network and document their open ports and services."},
    {"role": "user", "content": "[System Note: Target assigned.]\nPlease scan the following IP to discover its attack surface: 192.168.1.100"}
]

prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

print("\n--- TEST SCENARIO ---")
print("Input : An MQTT listener returning the exact [CACHE] string we trained on.")
print("Goal  : Verify if the model outputs valid JSON syntax without hallucinating.")
print("---------------------\n")

print("Generating response...")
with torch.no_grad():
    outputs = model.generate(
        **inputs, 
        max_new_tokens=150, 
        temperature=0.1, 
        do_sample=True, 
        pad_token_id=tokenizer.eos_token_id
    )

response = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)

print("\n--- MODEL OUTPUT ---")
print(response)
print("--------------------")
