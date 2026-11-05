"""Generates the CUTLASS SM90 GEMM variants for the GPU sweep, one small extension per variant.

out[m, n] = x[m, k] @ W[n, k]^T in BF16 with FP32 accumulation. "normal" variants tile (tokens, weight rows);
"swap" variants compute out^T = W x^T, tiling (weight rows, tokens), for few tokens. Kernels are TMA +
warp-specialized wgmma: ping-pong with the persistent scheduler, or cooperative with the stream-K scheduler.

    python3 gen_cutlass.py OUT_DIR   ->  OUT_DIR/v<id>.cu for every variant, and OUT_DIR/variants.json
"""

import json
import sys
from pathlib import Path

HEADER = r'''
#include <torch/extension.h>
#include <ATen/cuda/CUDAContext.h>
#include "cutlass/cutlass.h"
#include "cute/tensor.hpp"
#include "cutlass/gemm/device/gemm_universal_adapter.h"
#include "cutlass/gemm/kernel/gemm_universal.hpp"
#include "cutlass/gemm/collective/collective_builder.hpp"
#include "cutlass/epilogue/collective/collective_builder.hpp"
#include "cutlass/gemm/kernel/tile_scheduler_params.h"

using namespace cute;
using BF16 = cutlass::bfloat16_t;

template <class S> S k_major(int64_t rows, int64_t cols) { S s; get<0>(s) = cols; get<2>(s) = rows * cols; return s; }
template <class S> S m_major(int64_t rows, int64_t cols) { S s; get<1>(s) = rows; get<2>(s) = rows * cols; return s; }
'''

BODY = r'''
using Tile = Shape<_{tm}, _{tn}, _{tk}>;
using Cluster = Shape<_{cm}, _{cn}, _1>;
using LayoutD = cutlass::layout::{layout_d};
using Epi = typename cutlass::epilogue::collective::CollectiveBuilder<
    cutlass::arch::Sm90, cutlass::arch::OpClassTensorOp, Tile, Cluster,
    cutlass::epilogue::collective::EpilogueTileAuto, float, float,
    void, LayoutD, 8, BF16, LayoutD, 8, {epi}>::CollectiveOp;
using Main = typename cutlass::gemm::collective::CollectiveBuilder<
    cutlass::arch::Sm90, cutlass::arch::OpClassTensorOp,
    BF16, cutlass::layout::RowMajor, 8, BF16, cutlass::layout::ColumnMajor, 8, float, Tile, Cluster,
    cutlass::gemm::collective::StageCountAutoCarveout<static_cast<int>(sizeof(typename Epi::SharedStorage))>,
    {main}>::CollectiveOp;
using Kernel = cutlass::gemm::kernel::GemmUniversal<Shape<int, int, int, int>, Main, Epi, {sched}>;
using Gemm = cutlass::gemm::device::GemmUniversalAdapter<Kernel>;
constexpr bool SWAP = {swap};

void run(torch::Tensor x, torch::Tensor w, torch::Tensor out, torch::Tensor ws, int64_t mode, int64_t splits) {{
  int m = x.size(0), k = x.size(1), n = out.size(1);
  int M = SWAP ? n : m, N = SWAP ? m : n;
  auto* A = reinterpret_cast<BF16*>(SWAP ? w.data_ptr() : x.data_ptr());
  auto* B = reinterpret_cast<BF16*>(SWAP ? x.data_ptr() : w.data_ptr());
  auto* D = reinterpret_cast<BF16*>(out.data_ptr());
  auto sA = k_major<typename Kernel::StrideA>(M, k);
  auto sB = k_major<typename Kernel::StrideB>(N, k);
  typename Kernel::StrideD sD;
  if constexpr (SWAP) sD = m_major<typename Kernel::StrideD>(M, N); else sD = k_major<typename Kernel::StrideD>(M, N);
  typename Kernel::StrideC sC = sD;
  cutlass::KernelHardwareInfo hw;
  hw.device_id = x.get_device();
  hw.sm_count = cutlass::KernelHardwareInfo::query_device_multiprocessor_count(hw.device_id);
  typename Gemm::Arguments args{{cutlass::gemm::GemmUniversalMode::kGemm, {{M, N, k, 1}}, {{A, sA, B, sB}},
                                {{{{}}, nullptr, sC, D, sD}}, hw}};
  args.epilogue.thread.alpha = 1.0f;
  args.epilogue.thread.beta = 0.0f;
  if constexpr (std::is_same_v<typename Kernel::TileSchedulerTag, cutlass::gemm::StreamKScheduler>) {{
    using Mode = cutlass::gemm::kernel::detail::PersistentTileSchedulerSm90StreamKParams::DecompositionMode;
    args.scheduler.decomposition_mode = static_cast<Mode>(mode);
    args.scheduler.splits = (int)splits;
  }}
  Gemm gemm;
  TORCH_CHECK(gemm.can_implement(args) == cutlass::Status::kSuccess, "cutlass: cannot implement");
  TORCH_CHECK(Gemm::get_workspace_size(args) <= (size_t)ws.numel(), "cutlass: workspace too small");
  auto stream = at::cuda::getCurrentCUDAStream();
  TORCH_CHECK(gemm.initialize(args, ws.data_ptr(), stream) == cutlass::Status::kSuccess, "cutlass: initialize");
  TORCH_CHECK(gemm.run(stream) == cutlass::Status::kSuccess, "cutlass: run");
}}
'''

PP = ("cutlass::gemm::KernelTmaWarpSpecializedPingpong", "cutlass::epilogue::TmaWarpSpecialized",
      "cutlass::gemm::PersistentScheduler", "pingpong")
CO = ("cutlass::gemm::KernelTmaWarpSpecializedCooperative", "cutlass::epilogue::TmaWarpSpecializedCooperative",
      "cutlass::gemm::StreamKScheduler", "coop-streamk")


def variants():
    """Ping-pong only: cooperative stream-K, (1,2) clusters and 64x256 tiles all lost to cuBLAS in the H200 runs,
    while ping-pong 64x64x128 and 64x128x64 beat SGLang on the pooler at 128-256 tokens."""
    out = [("normal", PP, tile, (1, 1)) for tile in ((64, 64, 128), (64, 128, 64), (64, 128, 128), (64, 64, 256))]
    out.append(("normal", PP, (64, 128, 64), (2, 1)))  # untried: two token tiles share each weight tile (multicast)
    out += [("swap", PP, tile, (1, 1)) for tile in ((64, 16, 128), (64, 32, 128), (64, 64, 128))]
    return out


def main(out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    table = []
    for i, (orient, (main_s, epi_s, sched_s, kind), tile, cl) in enumerate(variants()):
        src = HEADER + BODY.format(tm=tile[0], tn=tile[1], tk=tile[2], cm=cl[0], cn=cl[1],
                                   layout_d="ColumnMajor" if orient == "swap" else "RowMajor",
                                   epi=epi_s, main=main_s, sched=sched_s,
                                   swap="true" if orient == "swap" else "false")
        (out_dir / f"v{i}.cu").write_text(src)
        table.append({"id": i, "orient": orient, "kind": kind, "tile": tile, "cluster": cl})
    (out_dir / "variants.json").write_text(json.dumps(table, indent=1))
    print(f"{len(table)} variants -> {out_dir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "cutlass_variants")
