# Local models for reverse engineering

Sources checked: **2026-11-03**. Research-based shortlist; **not benchmarked on local hardware**.
Use these as starting candidates, not a measured ranking for reverse engineering.

## Choose by VRAM

Assumes one GPU, one request at a time, full GPU offload, text only, and a recent compatible
GGUF runtime. Context is the **initial test setting**, including input and output tokens.
Thinking models need room for reasoning: at 16k or less, disable thinking (llama.cpp
`--reasoning off`) or lower the reasoning effort. The KV column is a calculated f16 estimate.
Weight sizes are publisher-reported decimal GB; GPU capacities are nominal GB classes.
Actual allocation includes KV cache, runtime buffers, and memory used by other applications.

| GPU VRAM | First candidate | Quant | Weights only | Start context | KV at start (calc.) | Fit estimate | Worth using? |
|---|---|---|---|---|---|---|---|
| 4 GB or less | No general recommendation | — | — | — | — | Too constrained | Skip a local model for serious RE. Use `analyze`, search, and your IDE. |
| 6 GB | Qwen3.5-4B | Q4_K_M | 2.74 GB | 16k | 0.5 GB | Likely | Small explanations or renaming suggestions. Usually not worth setting up for multi-file feature work. |
| 8 GB | Qwen3.5-9B | Q4_K_M | 5.68 GB | 16k | 0.5 GB | Limited headroom | Useful for one function at a time. Expect substantial manual correction. |
| 12 GB | Mellum2.1-12B-A2.5B-Thinking | Q4_K_M | 8.07 GB | 32k | 0.5 GB | Likely | Useful for bounded coding and tool-assisted investigation. Keep tasks small. Compare with Qwen3.5-9B Q6_K (7.46 GB). |
| 16 GB | Mellum2.1-12B-A2.5B-Thinking | Q6_K | 10.9 GB | 32k | 0.5 GB | Likely | Reasonable for small patches and feature components. Validate tool calls before relying on an agent loop. Compare with Qwen3.5-9B Q8_0 (9.53 GB). |
| 24 GB | Qwen3.8-27B | Q4_K_M | 19.0 GB | 32k | 2.1 GB | Likely; check free VRAM | Practical starting point for longer investigations and multi-file changes. Still needs review. |
| 32 GB | Qwen3.8-27B | Q8_0 | 28.6 GB | 32k | 2.1 GB | Tight | Useful. Q4 gives more context headroom if Q8 is tight; higher precision is not a guaranteed task improvement. |
| 48 GB | Qwen3.8-27B | Q8_0 | 28.6 GB | 64k | 4.3 GB | Comfortable | Useful with room for larger evidence bundles. Avoid squeezing Coder-Next Q4_K_M into this tier. |
| 64 GB | Qwen3-Coder-Next | Q4_K_M | 48.5 GB | 64k | 1.6 GB | Likely | Worth testing for sustained coding/tool work. Compare with Qwen3.8-27B Q8_0 on your actual tasks. |
| 96 GB | Qwen3-Coder-Next | Q6_K | 65.6 GB total | 128k | 3.2 GB | Likely | Useful capacity for larger tasks. Extra VRAM alone does not establish better accuracy or speed. |

**Practical cutoff:** below 8 GB, use a model only for small, supervised tasks. For interactive
work, spending hours forcing a large model into RAM with CPU offload is usually poor value.
CPU-only batch inference can still be useful when latency does not matter.

These are fit estimates, not memory guarantees. Leave roughly 2–4 GiB beyond weights for an
initial trial; the KV column excludes compute buffers. Measure actual peak allocation. Longer context or parallel requests can need
substantially more. Reduce context or use a smaller quant/model if allocation fails.
Apple unified memory is shared with the OS, IDE, and Ghidra: a 32 GB Mac is not a 32 GB dedicated
GPU. Multiple GPUs need explicit runtime support; their capacities are not automatically pooled.
VRAM capacity alone says little about response speed.

REA 6.8.0 exposes 229 MCP tools; their schemas take about 61k tokens (measured with the Qwen3.8
tokenizer). A client that sends all of them needs 96k–128k context; by calculation only the 12, 16, 48, 64
and 96 GB rows fit that. With less, allow only the REA tools the task needs, or paste evidence instead.

## ChatGPT / Claude reference

Approximate **task overlap**, not equal quality or a benchmark ranking. The local VRAM rows
above do not establish parity with any hosted model. These hosted models need no local GPU;
self-hosting their weights is not available. Access depends on the product, plan, and client.

| Task | Local setup to test | OpenAI reference | Claude reference |
|---|---|---|---|
| Explain a short function, extract strings, draft a small edit | 8–16 GB; narrow evidence | GPT-6 Luna | Haiku 5.5 |
| Implement a bounded feature across a few files | 12–32 GB; split and test each step | GPT-6.1 Sol | Sonnet 5.5 |
| Follow a long tool-driven investigation or substantial repository change | 24–96 GB; measure full-task success | GPT-6.1 Sol | Opus 5.5 |
| Resolve difficult, ambiguous behavior across many components | No established local equivalent in this guide | GPT-6 Astra | Fable 5.1 |

Use the hosted references as comparison runs on the same evidence and tests. A small local
model may handle a particular function well while failing the surrounding investigation.
Compare tool errors, manual corrections, and completion time, rather than parameter count.
OpenAI names here refer to **ChatGPT Work / Codex**; ordinary Chat can expose different choices.
Roles and current names: [official OpenAI documentation](https://learn.chatgpt.com/docs/models),
[Claude model overview](https://platform.claude.com/docs/en/models/overview). Task mapping is
editorial guidance, not a provider claim about reverse engineering.

## Exact downloads and sources

Use the named publisher and quant. GGUF files with similar names can have different sizes.
For sharded models, download every shard and count their combined size.

| Model | Model card | Quant publisher / file listing |
|---|---|---|
| Qwen3.5-4B / 9B | [4B](https://huggingface.co/Qwen/Qwen3.5-4B), [9B](https://huggingface.co/Qwen/Qwen3.5-9B) | [Unsloth 4B](https://huggingface.co/unsloth/Qwen3.5-4B-GGUF/tree/main), [Unsloth 9B](https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/tree/main): `Qwen3.5-{4B,9B}-Q4_K_M.gguf` |
| Mellum2.1 | [JetBrains](https://huggingface.co/JetBrains/Mellum2.1-12B-A2.5B-Thinking) | [Official GGUF](https://huggingface.co/JetBrains/Mellum2.1-12B-A2.5B-Thinking-GGUF/tree/main): `Mellum2.1-12B-A2.5B-Thinking-{Q4_K_M,Q6_K}.gguf` |
| Qwen3.8-27B | [Qwen](https://huggingface.co/Qwen/Qwen3.8-27B) | [ggml-org](https://huggingface.co/ggml-org/Qwen3.8-27B-GGUF/tree/main): `Qwen3.8-27B-{Q4_K_M,Q8_0}.gguf` (revision `a316ea5`); Unsloth `Qwen3.8-27B-UD-Q4_K_M.gguf` (16.46 GB) leaves more context room |
| Qwen3-Coder-Next | [Qwen](https://huggingface.co/Qwen/Qwen3-Coder-Next) | [Unsloth Q4](https://huggingface.co/unsloth/Qwen3-Coder-Next-GGUF/tree/main): `Qwen3-Coder-Next-Q4_K_M.gguf`; [Q6 shards](https://huggingface.co/unsloth/Qwen3-Coder-Next-GGUF/tree/main/Q6_K): all three `Qwen3-Coder-Next-Q6_K-*-of-00003.gguf` files |

Mellum is a coding/tool-use candidate at modest memory cost; Qwen3.8 is a general reasoning
candidate; Coder-Next targets agentic coding. Their published coding scores do not establish
accuracy on disassembly, ABI recovery, or game patches. MoE active parameter counts describe
compute, not resident weight memory: Coder-Next has 80B total parameters despite 3B active.
Optional vision projectors, draft models, and MTP heads are excluded from the table.
Templates: Qwen3.5/3.8 use reasoning `qwen3` and tools `qwen3_coder`; Mellum uses reasoning
`qwen3` and tools `hermes`; Coder-Next does not think and uses `qwen3_coder`. These are vLLM/SGLang
parser names; llama.cpp reads the template from the GGUF.
Check the license of both the original model and the chosen derivative before deployment.

## Alternatives to test

- **24–32 GB, MoE:** [Qwen3.6-35B-A3B](https://huggingface.co/Qwen/Qwen3.6-35B-A3B), [ggml-org Q4_K_M, 20.4 GB](https://huggingface.co/ggml-org/Qwen3.6-35B-A3B-GGUF/tree/main). Thinking model; small KV cache. Older non-thinking option: [Qwen3-Coder-30B-A3B-Instruct](https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct), [ggml-org Q4_K_M, 18.0 GB](https://huggingface.co/ggml-org/Qwen3-Coder-30B-A3B-Instruct-GGUF/tree/main); its KV cache limits 24 GB cards to about 32k.
- **24 GB, repository edits:** [Devstral Small 2 24B](https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512), [Unsloth Q4_K_M, 14.3 GB](https://huggingface.co/unsloth/Devstral-Small-2-24B-Instruct-2512-GGUF/tree/main). Check derivative licensing and runtime support. Upstream changed special tokens and tokenizer files in June–July 2026; current GGUFs predate that. Its KV cache is large (about 5.4 GB at 32k).
- **Small-model experiments:** [MiMo-V2.6-Distill-Qwen-9B](https://huggingface.co/XiaomiMiMo/MiMo-V2.6-Distill-Qwen-9B) ([bartowski Q4_K_M, 5.84 GB](https://huggingface.co/bartowski/MiMo-V2.6-Distill-Qwen-9B-GGUF/tree/main)) uses its own template and reasoning format; its card lists use restrictions, including malicious cyber activity. [Gemma 4 12B](https://huggingface.co/google/gemma-4-12B-it) ([Google QAT Q4_0, 6.98 GB](https://huggingface.co/google/gemma-4-12B-it-qat-q4_0-gguf/tree/main)) is another tool-use candidate; its tokenizer was fixed on 2026-10-30, after that GGUF. Neither has a validated REA configuration here.
- **Decompilation research:** [LLM4Decompile / SK²Decompile](https://github.com/albertan017/LLM4Decompile) specialize in assembly-to-C or decompiler-output refinement. Evaluate separately; they are not general feature-development agents. Weights are tagged MIT; the repository cites the DeepSeek License as well.
- **Recent, unverified:** [Flint](https://huggingface.co/RecursiveSI/flint) (39.8B MoE, [ggml-org Q4_K_M, 23.4 GB](https://huggingface.co/ggml-org/Flint-GGUF/tree/main)), released 2026-10-21; needs llama.cpp v0.8.0 or newer. Publisher scores only.

## Use with REA

`rea-suite analyze` works without a model or GPU. Run it first, then give the model relevant
functions, callers, strings, and addresses. Keep analysis outputs in the target project.

| Task | Give the model | Verify yourself |
|---|---|---|
| Explain a function | Pseudocode, assembly, callers, imports | Types, control flow, side effects |
| Find a hook candidate | Query hits, xrefs, call chain, target architecture | Address space, instruction boundaries, calling convention |
| Add a server browser | Network flow, packet format, UI call sites, editable source | Protocol compatibility, ownership/threading, tests |
| Prepare a patch | Original bytes, load address, ABI, expected behavior | Reassembly, relocation, rollback, runtime behavior |

A local server supplies inference. An agent client must separately support that endpoint,
REA's MCP tools, and the model's tool-call format. Codex needs a Responses API endpoint
(llama-server provides `/v1/responses`). Starting a server does not register REA or
make `analyze` use a model. `REA_SUITE_AGENT` selects the client command, not a model server.
The suite currently installs neither model weights nor an inference runtime.

Use a maintained runtime with support for the exact architecture, chat template, reasoning
mode, and tool parser. [llama-server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
enables Jinja templates by default and picks a tool-call handler from the template; check the
detected format in its log. An OpenAI-compatible
HTTP API alone does not prove correct tool use. Configure context explicitly; see
[Ollama's context and memory guidance](https://docs.ollama.com/context-length).
llama-server defaults to the model's full context and `--fit on`, which can shrink context or move
layers to the CPU; set `-c` and check the log. Ollama picks 4k–256k by VRAM and recommends at least
64k for agents; check `ollama ps`. Keep a loopback listener for local-only serving (llama-server
default: 127.0.0.1:9931).

## Validate before adopting

1. Start with the table's context and one request. Confirm full GPU offload and record peak memory.
2. Test one known function: explanation, xrefs, and one REA tool call. Compare against actual output.
3. Test a small, reversible repository change with existing tests. Check the diff and ABI assumptions.
4. Repeat representative tasks three times. Record success, malformed calls, total latency, and manual fixes.

Record model revision, exact quant files/checksums, runtime build, template/parser, GPU/backend,
context, KV-cache type, and results under `work/`. Increase context only after measuring fit.
Loading successfully is not a passing task result. Rebuildable source, disassembly, and runtime
evidence remain the checks on generated explanations and patches.

## Maintenance

`rea-suite update --ai` reviews this guide through
[updating-the-suite](../.agents/skills/updating-the-suite/SKILL.md), including releases, quant sizes,
runtime compatibility, and the VRAM verdicts. Research updates do not imply local benchmarks.
