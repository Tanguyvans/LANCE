import yaml
import torch
import os
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import load_dataset
from trl import SFTTrainer, DataCollatorForCompletionOnlyLM

def load_config(config_path: str):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def format_prompts_fn(examples, tokenizer):
    """
    Formats the messages list into a single text string using the tokenizer's chat template.
    """
    texts = []
    for messages in examples['messages']:
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
        texts.append(text)
    return {"text": texts}

def main():
    config_path = os.path.join(os.path.dirname(__file__), "configs", "qlora_config.yaml")
    config = load_config(config_path)

    # 1. Load Tokenizer
    model_id = config["model"]["name_or_path"]
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # 2. Load Dataset
    dataset_path = config["data"]["dataset_path"]
    dataset = load_dataset("json", data_files=dataset_path, split="train")
    
    # Format the dataset into the target chat template
    dataset = dataset.map(lambda x: format_prompts_fn(x, tokenizer), batched=True, remove_columns=dataset.column_names)

    # 3. Setup Quantization Configuration
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=config["bitsandbytes"]["load_in_4bit"],
        bnb_4bit_quant_type=config["bitsandbytes"]["bnb_4bit_quant_type"],
        bnb_4bit_use_double_quant=config["bitsandbytes"]["bnb_4bit_use_double_quant"],
        bnb_4bit_compute_dtype=getattr(torch, config["bitsandbytes"]["bnb_4bit_compute_dtype"])
    )

    # 4. Load Base Model
    print(f"Loading base model {model_id}...")
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=bnb_config,
        device_map="auto",
        attn_implementation=config["model"].get("attn_implementation", "sdpa")
    )
    model.config.use_cache = False # Required for gradient checkpointing
    model = prepare_model_for_kbit_training(model)

    # 5. Setup LoRA
    lora_config = LoraConfig(
        r=config["lora"]["r"],
        lora_alpha=config["lora"]["lora_alpha"],
        lora_dropout=config["lora"]["lora_dropout"],
        bias=config["lora"]["bias"],
        task_type=config["lora"]["task_type"],
        target_modules=config["lora"]["target_modules"]
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 6. Training Arguments
    training_args = TrainingArguments(
        output_dir=config["training"]["output_dir"],
        num_train_epochs=config["training"]["num_train_epochs"],
        per_device_train_batch_size=config["training"]["per_device_train_batch_size"],
        gradient_accumulation_steps=config["training"]["gradient_accumulation_steps"],
        learning_rate=config["training"]["learning_rate"],
        weight_decay=config["training"]["weight_decay"],
        max_grad_norm=config["training"]["max_grad_norm"],
        warmup_ratio=config["training"]["warmup_ratio"],
        lr_scheduler_type=config["training"]["lr_scheduler_type"],
        logging_steps=config["training"]["logging_steps"],
        save_strategy=config["training"]["save_strategy"],
        optim=config["training"]["optim"],
        report_to=config["training"].get("report_to", "none"),
        fp16=False,
        bf16=True, # Llama-3 performs better with bf16
        gradient_checkpointing=True
    )

    # 7. Initialize Trainer
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        peft_config=lora_config,
        dataset_text_field="text",
        max_seq_length=config["training"]["max_seq_length"],
        tokenizer=tokenizer,
        args=training_args,
        packing=False
    )

    # 8. Train
    print("Starting training...")
    trainer.train()

    # 9. Save final adapters
    trainer.model.save_pretrained(config["training"]["output_dir"])
    tokenizer.save_pretrained(config["training"]["output_dir"])
    print(f"Training complete. Adapters saved to {config['training']['output_dir']}")

if __name__ == "__main__":
    main()
