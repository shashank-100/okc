"""Builds muse_decode_layer/submission_<tag>.py from our own pieces: the decode-layer glue (d3) with its
expert block replaced by our MoE kernel (muse_moe_w4a16 submission_m18.py).

python3 tools/build_dl.py <tag> [moe_file]
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
tag = sys.argv[1]
moe_file = sys.argv[2] if len(sys.argv) > 2 else "submission_m18.py"

dl = (ROOT / "muse_decode_layer/submission_d3.py").read_text()
moe = (ROOT / "muse_moe_w4a16" / moe_file).read_text()

# MoE module: drop its problem header and TypedDicts, rename its entry points.
moe = moe.split("\n", 1)[1]
for cls in ("Weights", "Config", "Inputs"):
    moe = re.sub(rf"\nclass {cls}\(TypedDict\):\n(?:    .*\n|\n)*?(?=\n\S)", "\n", moe)
moe = moe.replace("\ndef prepare(weights):", "\ndef _moe_prepare(weights):")
moe = moe.replace("\ndef kernel_fn(data, state):", "\ndef _moe_kernel_fn(data, state):")
assert "def _moe_prepare" in moe and "def _moe_kernel_fn" in moe
assert "class Weights" not in moe

# Decode layer: prepare builds the MoE state; _experts calls our kernel.
old_bank = '        "bank": _marlin_bank(weights),\n'
assert old_bank in dl
dl = dl.replace(old_bank, '        "moe": _moe_prepare({k: weights[k] for k in ("w13", "w13_sf", "w13_gs", "w2", "w2_sf", "w2_gs")}\n'
                          '                            | {"post_norm_w": weights["post_expert_norm"]}),\n')
start = dl.index("def _experts(x, topk_weights, topk_ids, state):")
end = dl.index("def kernel_fn(data, state):")
dl = dl[:start] + '''def _experts(x, topk_weights, topk_ids, state):
    """Our NVFP4 expert kernels (muse_moe_w4a16 m18) on this GPU's experts 0-31, post-expert norm included."""
    data = {"hidden_states": x, "topk_ids": topk_ids.to(torch.int32), "topk_weights": topk_weights.to(torch.float32),
            "config": {"bs": x.shape[0], "d_hidden": D_EXPERT, "d_expert": D_EXPERT, "n_experts": N_EXPERTS,
                       "local_start": 0, "local_count": LOCAL_EXPERTS, "top_k": TOP_K, "sharding": "ep8"}}
    return _moe_kernel_fn(data, state["moe"])


''' + dl[end:]

marker = "\ndef prepare(weights):"
dl = dl.replace(marker, "\n# ---- our MoE kernels, from muse_moe_w4a16/" + moe_file + " ----\n" + moe + "\n" + marker, 1)

out = ROOT / "muse_decode_layer" / f"submission_{tag}.py"
out.write_text(dl)
print(out, len(dl.splitlines()), "lines")
