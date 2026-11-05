"""Builds every CUTLASS variant from gen_cutlass.py as its own torch extension, in parallel; one that fails to
compile is reported and skipped, never blocks the rest.

    python3 build_variants.py VARIANT_DIR [jobs]   ->  prints which variants built; importable via load_variants()
"""

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.setdefault("TORCH_CUDA_ARCH_LIST", "9.0a")
CUTLASS = os.environ.get("CUTLASS_DIR", "/opt/cutlass")
FLAGS = ["-O3", "-std=c++20", "--expt-relaxed-constexpr", "-DNDEBUG", "-gencode=arch=compute_90a,code=sm_90a"]
BINDING = 'void run(torch::Tensor x, torch::Tensor w, torch::Tensor out, torch::Tensor ws, int64_t mode, int64_t splits);\n'


def _build(vdir, i):
    from torch.utils.cpp_extension import load_inline
    t = time.time()
    try:
        mod = load_inline(f"okc_cut_v{i}", cpp_sources=BINDING, cuda_sources=(vdir / f"v{i}.cu").read_text(),
                          functions=["run"], with_cuda=True, verbose=False,
                          extra_include_paths=[f"{CUTLASS}/include", f"{CUTLASS}/tools/util/include"],
                          extra_cuda_cflags=FLAGS)
        return i, mod, time.time() - t, None
    except Exception as e:
        errs = [l for l in str(e).splitlines() if "error" in l.lower()][:4]
        return i, None, time.time() - t, " | ".join(errs)[:600]


def load_variants(vdir, jobs=None):
    """{variant id: (module, description)} for every variant that builds."""
    vdir = Path(vdir)
    table = {v["id"]: v for v in json.loads((vdir / "variants.json").read_text())}
    jobs = jobs or max(1, (os.cpu_count() or 4) // 2)
    built = {}
    with ThreadPoolExecutor(jobs) as pool:
        for i, mod, secs, err in pool.map(lambda i: _build(vdir, i), sorted(table)):
            v = table[i]
            desc = f"{v['orient']}/{v['kind']}/{'x'.join(map(str, v['tile']))}/c{'x'.join(map(str, v['cluster']))}"
            print(f"v{i:<3d} {desc:40s} {'built' if mod else 'FAILED'} {secs:5.0f}s {err or ''}", flush=True)
            if mod:
                built[i] = (mod, v)
    return built


if __name__ == "__main__":
    t0 = time.time()
    got = load_variants(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else None)
    print(f"{len(got)} variants built in {time.time() - t0:.0f} s")
