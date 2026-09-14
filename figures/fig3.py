"""Figure 3: operation scaling (a) + sign (b) / verify (c) latency breakdowns.

Style follows user-selected AgentFigureGallery references (gramm/ggplot grouped
boxes with spacing + jittered raw points; raincloud-style distribution display).
Data: per-repetition raw measurements; no CSV is modified.
"""
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent / "results" / "fig3"
OUT = BASE

# ---------------------------------------------------------------- style
mpl.rcParams.update({
    "font.size": 7.2, "axes.labelsize": 7.6, "axes.titlesize": 8.0,
    "xtick.labelsize": 6.8, "ytick.labelsize": 6.8, "legend.fontsize": 6.6,
    "font.family": "sans-serif", "axes.spines.top": False,
    "axes.spines.right": False, "axes.linewidth": 0.7,
    "xtick.major.width": 0.7, "ytick.major.width": 0.7,
    "xtick.major.size": 2.4, "ytick.major.size": 2.4,
    "legend.frameon": False, "figure.dpi": 200, "savefig.dpi": 300,
    "savefig.bbox": "tight", "pdf.fonttype": 42,
})

C_T = {1024: "#0072B2", 65536: "#E69F00", 1048576: "#009E73"}  # Okabe-Ito
C_OP = {"keygen": "#0072B2", "sign": "#D55E00", "verify": "#009E73",
        "evolve": "#CC79A7"}
TICK = {1024: r"$2^{10}$", 65536: r"$2^{16}$", 1048576: r"$2^{20}$"}

# ---------------------------------------------------------------- data
scal = pd.read_csv(BASE / "operation_scaling_raw.csv")
scal = scal[scal.op.isin(C_OP)]

sign = pd.read_csv(BASE / "signbd_raw.csv")          # per-rep sign breakdown
verb = pd.read_csv(BASE / "verbd_raw.csv")           # per-rep verify breakdown
verb = verb[pd.to_numeric(verb["T"], errors="coerce").notna()].astype(
    {"T": int})
floor = verb.loc[verb["T"] == 0, "fswa_us"].median()  # plain ML-DSA verify
verb = verb[verb["T"] > 0]

SIGN_STAGES = [("msg_us", "msg\nbuild"), ("fswa_us", "ML-DSA\nsign"),
               ("path_us", "path &\npackaging")]
VERB_STAGES = [("parse_us", "parse &\nreconstruct"),
               ("merkle_us", "Merkle\npath"), ("fswa_us", "ML-DSA\nverify")]

# ---------------------------------------------------------------- helpers
def box_strip(ax, df, stages, ylab):
    """Grouped boxes (stage on x, T as fill) with jittered raw points."""
    nT, nS = len(C_T), len(stages)
    width, gap = 0.24, 0.06                      # box width / intra-group gap
    group_w = nT * width + (nT - 1) * gap
    for si, (col, _) in enumerate(stages):
        center = si
        x0 = center - group_w / 2 + width / 2
        for ti, (T, color) in enumerate(C_T.items()):
            x = x0 + ti * (width + gap)
            vals = df.loc[df["T"] == T, col].to_numpy()
            bp = ax.boxplot(vals, positions=[x], widths=width * 0.92,
                            patch_artist=True, showfliers=False,
                            whis=(5, 95),
                            medianprops=dict(color="black", lw=0.8),
                            whiskerprops=dict(lw=0.7, color="0.25"),
                            capprops=dict(lw=0.7, color="0.25"),
                            boxprops=dict(lw=0.6, edgecolor="0.2"))
            bp["boxes"][0].set_facecolor(color)
            bp["boxes"][0].set_alpha(0.55)
            rng = np.random.default_rng(1234 + si * 10 + ti)
            jitter = rng.uniform(-width * 0.42, width * 0.42, vals.size)
            ax.plot(x + jitter, vals, ".", ms=0.9, mew=0, color=color,
                    alpha=0.30, rasterized=True)
    ax.set_xticks(range(nS))
    ax.set_xticklabels([lab for _, lab in stages])
    ax.set_yscale("log")
    ax.set_ylabel(ylab)
    lo = min(df[c].min() for c, _ in stages)
    hi = max(df[c].max() for c, _ in stages)
    ax.set_ylim(lo * 0.6, hi * 1.6)
    ax.yaxis.grid(True, color="0.88", lw=0.5)
    ax.set_axisbelow(True)
    ax.set_xlim(-0.65, nS - 0.35)

# ---------------------------------------------------------------- figure
fig, axes = plt.subplots(1, 3, figsize=(7.16, 2.5),
                         gridspec_kw={"width_ratios": [1.25, 1.0, 1.0]})

# --- (a) operation scaling, log-log with p25-p75 band
ax = axes[0]
for op, color in C_OP.items():
    d = scal[scal.op == op].sort_values("T")
    ax.plot(d["T"], d["median_us"], "-o", color=color, lw=1.1, ms=2.4,
            label=op, zorder=3)
    ax.fill_between(d["T"], d["p25_us"], d["p75_us"], color=color,
                    alpha=0.16, lw=0, zorder=2)
ax.set_xscale("log", base=2)
ax.set_yscale("log")
ax.set_xticks(sorted(scal["T"].unique()))
ax.set_xticklabels([r"$2^{%d}$" % np.log2(t) for t in sorted(scal["T"].unique())])
ax.minorticks_off()
ax.set_xlabel("tree size $T$")
ax.set_ylabel("latency (µs)")
ax.yaxis.grid(True, color="0.88", lw=0.5)
ax.set_axisbelow(True)
ax.legend(loc="upper left", handlelength=1.4, labelspacing=0.25, borderpad=0.2)
ax.set_title("operation latency vs. tree size", fontsize=7.4, pad=3)

# --- (b) sign breakdown
ax = axes[1]
box_strip(ax, sign, SIGN_STAGES, "latency (µs)")
ax.set_title("sign breakdown ($n{=}1000$/T)", fontsize=7.4, pad=3)

# --- (c) verify breakdown + plain-ML-DSA floor
ax = axes[2]
box_strip(ax, verb, VERB_STAGES, "latency (µs)")
xlim = ax.get_xlim()
ax.plot([xlim[0], xlim[1]], [floor, floor], ls="--", lw=0.9, color="0.15",
        zorder=4)
ax.annotate("plain ML-DSA floor\n(%.1f µs, $T{=}0$)" % floor,
            xy=(2.15, floor), xytext=(1.28, floor * 1.9), fontsize=6.0,
            ha="left", va="bottom", color="0.15",
            arrowprops=dict(arrowstyle="-", lw=0.5, color="0.3"))
ax.set_title("verify breakdown ($n{=}1000$/T)", fontsize=7.4, pad=3)

# shared T legend for (b), (c)
handles = [mpl.patches.Patch(facecolor=c, alpha=0.55, edgecolor="0.2",
                             lw=0.6, label=TICK[t]) for t, c in C_T.items()]
fig.legend(handles=handles, loc="lower center", ncol=3,
           bbox_to_anchor=(0.645, -0.06), handlelength=1.2,
           columnspacing=1.2, title="tree size $T$",
           title_fontsize=6.8, alignment="center")

for ax, lab in zip(axes, "abc"):
    ax.text(-0.18 if lab == "a" else -0.26, 1.06, f"$\\mathbf{{{lab}}}$",
            transform=ax.transAxes, fontsize=9.5, va="top", ha="left")

fig.subplots_adjust(wspace=0.34, left=0.065, right=0.995, top=0.90,
                    bottom=0.20)
fig.savefig(OUT / "fig3.pdf")
fig.savefig(OUT / "fig3.png")
print("saved:", OUT / "fig3.png")
