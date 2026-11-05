# OKC — Muse Spark Open kernels

Our submissions to the Open Kernel Challenge (Muse Spark Open, 8×H200 serving).
Every score is a **speedup × over the SGLang baseline**, judge-measured on H200
(cold-L2 CUDA-graph medians). Team `shashank-100`.

## Best scores on the boards

| Problem | Best score | Rank | 1st place | Board run | Kernel |
|---|---|---|---|---|---|
| `muse_attention_decode` | **2.614×** | 298 | 3.3389× (pjmullin3) | `bd54d2d9f4a14522` | `submission_best.py` |
| `muse_moe_w4a16` | **2.3292×** | 430 | 2.8003× (LeshengJin) | `c71e759981c8439c` | `submission_best.py` |
| `muse_decode_layer` | **2.0915×** | 486 | 2.5772× (gogowhy) | `f02e93cb07b24f46` | `submission_best.py` |
| `muse_prefill_layer` | **1.7984×** | 254 | 2.1471× (LeshengJin) | `29f18053b93d4dfa` | `submission_best.py` |
| `muse_bf16_proj` | **1.4591×** | 456 | 1.7277× (gogowhy) | `d34d184de2e344d5` | `submission_v25.py` |

Each problem directory's `submission.py` is the kernel behind its board entry
(one file, first line `# okc: problem=<problem>`), with its board job and verified
check score in the header.

## Repo layout

```
muse_attention_decode/   gated attention decode over a paged FP8 cache
muse_bf16_proj/          dense BF16 projections + FP32 router
muse_decode_layer/       whole decoder layer under TP8/EP8
muse_moe_w4a16/          top-8/256 routed experts, NVFP4 weights
muse_prefill_layer/      prefill layer (16K-token first turns)
```

Per directory: `submission.py` — our board kernel, ready to submit — its named
copy (`submission_best.py` / `submission_v25.py`), and the problem spec (`TASK.md`,
`reference.py`, `checks.py`).

How each kernel works is in [APPROACHES.md](APPROACHES.md).

## Commands

```bash
okc check <problem> submission.py --json   # judge tests + timing, off the board
okc submit <problem> submission.py --json  # scored run
okc leaderboard <problem> --json           # board standings
```
