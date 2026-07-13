import torch
import argparse
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

def main(base_model_id: str, adapter_dir: str):
    print(f"Loading tokenizer from {base_model_id}")
    tokenizer = AutoTokenizer.from_pretrained(base_model_id)

    print(f"Loading base model {base_model_id} in bfloat16")
    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        torch_dtype=torch.bfloat16,
        device_map="auto"
    )

    print(f"Loading LoRA adapters from {adapter_dir}")
    model = PeftModel.from_pretrained(base_model, adapter_dir)
    model.eval()

    print("Model ready for inference. Type 'quit' or 'exit' to stop.")
    
    # Simple interactive prompt
    messages = [
        {"role": "system", "content": "You are LANCE, an autonomous LLM Agent for Network Compromise Evaluation."}
    ]

    while True:
        user_input = input("\nUser: ")
        if user_input.lower() in ["quit", "exit"]:
            break

        messages.append({"role": "user", "content": user_input})
        
        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        
        with torch.no_grad():
            outputs = model.generate(
                **inputs, 
                max_new_tokens=512,
                temperature=0.7,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id
            )
            
        generated_tokens = outputs[0][inputs.input_ids.shape[1]:]
        response = tokenizer.decode(generated_tokens, skip_special_tokens=True)
        
        print(f"\nAssistant: {response}")
        messages.append({"role": "assistant", "content": response})

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base_model", type=str, default="meta-llama/Meta-Llama-3-8B-Instruct", help="The Hugging Face ID of the base model")
    parser.add_argument("--adapter_dir", type=str, default="output/adapters/lance-qlora", help="Path to the trained LoRA adapters")
    args = parser.parse_args()
    
    main(args.base_model, args.adapter_dir)
