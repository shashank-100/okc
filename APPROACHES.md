# Approaches

How each of our board kernels works, per problem. Scores are speedup × over SGLang
on the judge's H200 harness.

---

## muse_attention_decode — board best 2.614×

**Task.** One decode step or an 8-token verify block of grouped-query attention over
a paged FP8 cache: QK-norm, a 2,048-token sliding window with RoPE or full attention
over ~80K-token contexts, and a gated, normalized output. SGLang runs seven kernels
per call; the whole step is a few hundred KB of work, so launches dominate.

### Board kernel (`submission_best.py`, 2.614×)

One fused CUDA kernel per call. Everything SGLang splits into seven launches —
per-head RMSNorm of q and k, interleaved RoPE on sliding layers, the FP8 casts, the
cache store, the query cast, the paged attention, and the output norm-gate — happens
inside a single launch. A program owns one request, one key/value head and one slice
of the cached keys (more slices on long contexts so every SM streams keys): it norms
and ropes its queries, rounds the new keys/values through the FP8 cache format,
writes them to the cache, then runs an online softmax over its FP8 slice decoded
exactly to BF16, applies the sliding window per query token, attends the causal tail,
and applies the norm-gate. Verify blocks and full-attention layers use a split-KV
flash path on tensor cores straight from the scattered FP8 cache rows, with a split
combine and the gate fused into the epilogue.

---

## muse_bf16_proj — board best 1.4591×

**Task.** The attention/MoE projections and the router as one GPU serves them:
`out = x @ W.T`, BF16 weights (router FP32), m ∈ {1, 16, 32} decode and
{8, 128, 256} verify tokens. Weights arrive once, untimed, in `prepare()`.

### Board kernel (`submission_v25.py`, 1.4591×, submitted from this repo)

Stream-K skinny GEMM: `out[m, n] = x @ W[:n].T` for m ≤ 32 and the router at any m.
The weight is the large operand, so work is cut into K-range slices spread across the
GPU's 132 SMs; per-shape dispatch is tuned in `prepare()` on the judge GPU with
CUDA-graph-replay timing. Small-m shapes run register-direct; the router keeps FP32
fidelity. Its 10-28 check measured 1.4492×; the 11-05 submission measured 1.4591×
(rank 850 → 456).

---

## muse_moe_w4a16 — board best 2.3292×

**Task.** Top-8 of 256 experts at width 4096: SwiGLU, NVFP4 weights, a per-expert
output norm before the weighted sum. Only the GPU's local experts arrive.

### Board kernel (`submission_best.py`, 2.3292×)

A per-M family of CUDA expert GEMMs, tuned in `prepare()` per routing bucket on the
judge GPU:

- **g1** (M ≤ 2): every warp owns a 256-K slice of every weight row of its CTA;
  activation slice in registers, one 16-way smem reduction per tile; W13 over a
  contiguous tile range of all local experts, then W2 by output-row tiles with full
  K — no fp32 atomics, three grid barriers.
- **gk** (3 ≤ M ≤ 32): all M activation rows in smem; 16 warps as tile groups
  splitting K behind group-local named barriers; W2 K split over CTA groups with
  fp32 partials in global.
- **fs** (fused split-K, M ≤ 32): each CTA owns one 32-column intermediate granule
  per active expert, streaming W13 rows and the matching W2 column slice back to
  back — no W13→W2 grid dependency.
- **wx** (M ≥ 32): one-pass-per-expert wgmma RS GEMM — 128-row units over all of an
  expert's tokens, 64-K chunk slots of TMA weights, gathered pre-swizzled
  activations, wgmma descriptors held on the uniform datapath.

All consumers share an 8-op e2m1→BF16 dequant placement (5 LOP3 + 2 SHF.W + 1 IMAD
per word instead of 11 integer ops), with per-piece scale-byte variants; `prepare()`
repacks nibbles to match.

---

## muse_decode_layer — board best 2.0915×

**Task.** Everything one GPU does for one layer of Muse Spark Open under TP8/EP8:
projections, attention, router, top-8 experts, every norm and residual in between.

### Board kernel (`submission_best.py`, 2.0915×)

The whole layer as few launches as possible: c12 register-direct GEMV and wgmma
routers, cuBLAS projections, fused split-KV FP8 attention, fused residual norms, and
the NVFP4 W4A16 MoE — with **PDL (programmatic dependent launch) selectable per
(kernel, T)** so consecutive kernels overlap their prologues on the same SM.

---

## muse_prefill_layer — board best 1.7984×

**Task.** The same layer at prefill sizes — 16K-token first-turn loads among three
equally weighted score components. A separate board.

### Board kernel (`submission_best.py`, 1.7984×)

cuBLAS projections + FA3 with a fused prologue/epilogue + fused residual norms +
Marlin/dequant + grouped GEMM MoE with all the glue fused around them.

---

## Cross-cutting lessons

- **Time CUDA graph replays, never eager launches** — at these sizes eager timing
  inverts rankings; the judge times graph replays with cold L2.
- **Adopt only beyond a margin** — a 3% measured margin (checks vs incumbent) kept
  every tuned dispatch honest and rejected every warmup/order artifact.
- **`prepare()` is free compute** — weight repacking, per-shape route tuning, and
  self-validation against FP32/FP64 references all happen untimed before the clock
  starts.
- **One kernel per call where launches dominate** (small decode steps), **few
  tensor-core kernels where math dominates** (prefill experts).
