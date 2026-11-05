
#include <cstdio>
#include <stdexcept>
#include <cuda_runtime.h>
#define TORCH_CHECK(c, ...) do { if (!(c)) throw std::runtime_error("check"); } while (0)
#include "cutlass/cutlass.h"
#include "cute/tensor.hpp"
#include "cutlass/gemm/device/gemm_universal_adapter.h"
#include "cutlass/gemm/kernel/gemm_universal.hpp"
#include "cutlass/gemm/collective/collective_builder.hpp"
#include "cutlass/epilogue/collective/collective_builder.hpp"
#include "cutlass/gemm/kernel/tile_scheduler_params.h"

using namespace cute;
using BF16 = cutlass::bfloat16_t;

template <class Tile, class Cluster, class LayoutD>
struct Cfg {
  using LayoutA = cutlass::layout::RowMajor;
  using LayoutB = cutlass::layout::ColumnMajor;
  using Epi = typename cutlass::epilogue::collective::CollectiveBuilder<
      cutlass::arch::Sm90, cutlass::arch::OpClassTensorOp, Tile, Cluster,
      cutlass::epilogue::collective::EpilogueTileAuto, float, float,
      void, LayoutD, 8, BF16, LayoutD, 8,
      cutlass::epilogue::TmaWarpSpecializedCooperative>::CollectiveOp;
  using Main = typename cutlass::gemm::collective::CollectiveBuilder<
      cutlass::arch::Sm90, cutlass::arch::OpClassTensorOp,
      BF16, LayoutA, 8, BF16, LayoutB, 8, float, Tile, Cluster,
      cutlass::gemm::collective::StageCountAutoCarveout<static_cast<int>(sizeof(typename Epi::SharedStorage))>,
      cutlass::gemm::KernelTmaWarpSpecializedCooperative>::CollectiveOp;
  using Kernel = cutlass::gemm::kernel::GemmUniversal<Shape<int, int, int, int>, Main, Epi, cutlass::gemm::StreamKScheduler>;
  using Gemm = cutlass::gemm::device::GemmUniversalAdapter<Kernel>;
};

using C0 = Cfg<Shape<_128, _128, _64>, Shape<_1, _1, _1>, cutlass::layout::RowMajor>;
using C1 = Cfg<Shape<_128, _128, _64>, Shape<_1, _2, _1>, cutlass::layout::RowMajor>;
using C2 = Cfg<Shape<_128, _32, _128>, Shape<_1, _1, _1>, cutlass::layout::ColumnMajor>;

template <class S> S k_major(int64_t rows, int64_t cols) {  // (rows, cols) with cols contiguous
  S s; get<0>(s) = cols; get<2>(s) = rows * cols; return s;
}
template <class S> S m_major(int64_t rows, int64_t cols) {  // (rows, cols) with rows contiguous
  S s; get<1>(s) = rows; get<2>(s) = rows * cols; return s;
}

template <class C, bool SWAP>
void run(const void* xp, const void* wp, void* outp, void* wsp, size_t ws_bytes, int m, int k, int n, int mode, int splits, cudaStream_t stream) {
  using Gemm = typename C::Gemm;
  using K = typename C::Kernel;
  int M = SWAP ? n : m, N = SWAP ? m : n;
  auto* A = reinterpret_cast<const BF16*>(SWAP ? wp : xp);
  auto* B = reinterpret_cast<const BF16*>(SWAP ? xp : wp);
  auto* D = reinterpret_cast<BF16*>(outp);
  auto sA = k_major<typename K::StrideA>(M, k);
  auto sB = k_major<typename K::StrideB>(N, k);
  typename K::StrideD sD;
  if constexpr (SWAP) sD = m_major<typename K::StrideD>(M, N); else sD = k_major<typename K::StrideD>(M, N);
  typename K::StrideC sC = sD;
  cutlass::KernelHardwareInfo hw;
  hw.device_id = 0;
  hw.sm_count = 132;
  typename Gemm::Arguments args{cutlass::gemm::GemmUniversalMode::kGemm, {M, N, k, 1}, {A, sA, B, sB},
                                {{}, nullptr, sC, D, sD}, hw};
  args.epilogue.thread.alpha = 1.0f;
  args.epilogue.thread.beta = 0.0f;
  using Mode = cutlass::gemm::kernel::detail::PersistentTileSchedulerSm90StreamKParams::DecompositionMode;
  args.scheduler.decomposition_mode = static_cast<Mode>(mode);
  args.scheduler.splits = splits;
  Gemm gemm;
  TORCH_CHECK(gemm.can_implement(args) == cutlass::Status::kSuccess, "cutlass: cannot implement");
  size_t need = Gemm::get_workspace_size(args);
  TORCH_CHECK(need <= ws_bytes, "ws");
  TORCH_CHECK(gemm.initialize(args, wsp, stream) == cutlass::Status::kSuccess, "init");
  TORCH_CHECK(gemm.run(stream) == cutlass::Status::kSuccess, "run");
}

template void run<C0, false>(const void*, const void*, void*, void*, size_t, int, int, int, int, int, cudaStream_t);
template void run<C1, false>(const void*, const void*, void*, void*, size_t, int, int, int, int, int, cudaStream_t);
template void run<C2, true>(const void*, const void*, void*, void*, size_t, int, int, int, int, int, cudaStream_t);
