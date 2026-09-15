"""Dataset preparation preserves complete intrusion evidence chains."""

class TestPrepare3BDatasets:
    def test_phase5_examples_remain_single_atomic_evidence_chain(self):
        from model_training.prepare_3b_datasets import build_chunks

        class Tokenizer:
            def apply_chat_template(
                self, messages, tools=None, tokenize=False, add_generation_prompt=False
            ):
                return "\n".join(str(message.get("content", "")) for message in messages)

            def encode(self, text, add_special_tokens=False):
                return text.split()

        row = {
            "metadata": {"phase": 5},
            "tools": [],
            "messages": [
                {"role": "system", "content": "intrusion system"},
                {"role": "user", "content": "use tool evidence"},
                {"role": "assistant", "content": "try credential"},
                {"role": "tool", "content": "try_credential success false"},
                {"role": "assistant", "content": "final no compromise"},
            ],
        }

        chunks, stats = build_chunks(Tokenizer(), row, max_length=100, distractors=0)

        assert stats["chunks"] == 1
        assert len(chunks) == 1
        assert chunks[0]["metadata"]["evidence_chain_atomic"] is True
        contents = [message.get("content") for message in chunks[0]["messages"]]
        assert "try_credential success false" in contents
        assert "final no compromise" in contents
