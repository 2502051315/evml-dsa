"""Figure 4 — batch throughput, rechain cost, archive scaling (IEEE double-col).

Reference DNA: BAR-876A13AE7A (ggplot2 grouped-bar style template, selected in
the AgentFigureGallery bar_chart session) drives panel (a): grouped flat-fill
bars with thin dark outlines and q1–q3 whisker caps. Panels (b)(c) carry over
the established Figure-3 language (dominant boxes over faint jitter; median
line + band; Okabe-Ito; white bg, light grid, no top/right spines).

Data (read-only inputs in ./):
  fig4_throughput.csv        (a) 2 schemes x 5 batch sizes, median/q1/q3 tps
  rechain_distance_raw.csv   (b) verify_us, evmldsa d=0 (n=300) + rechain
                             d in {1..64} (n=100 each)
  archive_scaling_raw.csv    (c) 5 archive sizes x 3 reps, total_s
                             (numeric-coerced; drops the trailing
                             "RE RUN_DONE" marker row)
"""
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent / "results" / "fig4"
OUT = BASE

mpl.rcParams.update({
    "font.size": 7.0, "axes.labelsize": 7.2, "axes.titlesize": 7.4,
    "xtick.labelsize": 6.4, "ytick.labelsize": 6.4, "legend.fontsize": 6.2,
    "font.family": "sans-serif",
    "figure.facecolor": "white", "axes.facecolor": "white",
    "savefig.facecolor": "white",
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.linewidth": 0.6, "xtick.major.width": 0.6,
    "ytick.major.width": 0.6, "xtick.major.size": 2.2,
    "ytick.major.size": 2.2,
    "legend.frameon": False, "figure.dpi": 200, "savefig.dpi": 300,
    "savefig.bbox": "tight", "pdf.fonttype": 42,
})

C_EV, C_PL = "#0072B2", "#E69F00"  # Okabe-Ito: evML-DSA / plain ML-DSA
C_RC = "#0072B2"
GRID = dict(color="0.95", lw=0.3)

thr = pd.read_csv(BASE / "fig4_throughput.csv")
rec = pd.read_csv(BASE / "rechain_distance_raw.csv")
arc = pd.read_csv(BASE / "archive_scaling_raw.csv")
for c in ("n_records", "total_s", "per_record_us"):
    arc[c] = pd.to_numeric(arc[c], errors="coerce")
arc = arc.dropna(subset=["n_records", "total_s"])

fig, axes = plt.subplots(1, 3, figsize=(7.16, 2.55),
                         gridspec_kw={"width_ratios": [1.0, 1.22, 0.95]})

# --- (a) throughput vs batch size: grouped bars + q1-q3 caps (ref style) ---
ax = axes[0]
batches = [1, 10, 100, 1000, 10000]
schemes = [("evML-DSA", C_EV), ("plain ML-DSA", C_PL)]
w = 0.36
for si, (sch, color) in enumerate(schemes):
    d = thr[thr.scheme == sch].set_index("batch").loc[batches]
    x = np.arange(len(batches)) + (si - 0.5) * (w + 0.04)
    ax.bar(x, d.median_tps, width=w, color=color, alpha=0.85,
           edgecolor="0.15", lw=0.6, zorder=3)
    err = np.vstack([d.median_tps - d.q1_tps, d.q3_tps - d.median_tps])
    ax.errorbar(x, d.median_tps, yerr=err, fmt="none", ecolor="0.15",
                elinewidth=0.6, capsize=1.8, capthick=0.6, zorder=4)
ax.set_xticks(np.arange(len(batches)))
ax.set_xticklabels([str(b) for b in batches])
ax.set_xlabel("batch size $B$")
ax.set_ylabel("throughput (signatures/s)")
ax.set_ylim(0, 6800)
ax.yaxis.grid(True, **GRID)
ax.set_axisbelow(True)
ax.set_title("Signing throughput vs. batch size", pad=3)
handles = [mpl.patches.Patch(facecolor=c, alpha=0.85, edgecolor="0.15",
                             lw=0.6, label=s) for s, c in schemes]
ax.legend(handles=handles, loc="upper right", ncol=1, handlelength=1.1,
          labelspacing=0.3, borderpad=0.25)

# --- (b) verify latency vs rechain distance: boxes over faint jitter ---
ax = axes[1]
ds = [0, 1, 2, 4, 8, 16, 32, 64]
for xi, d in enumerate(ds):
    vals = rec.loc[rec.d == d, "verify_us"].to_numpy()
    rng = np.random.default_rng(4200 + d)
    ax.plot(xi + rng.uniform(-0.17, 0.17, vals.size), vals, ".",
            ms=0.5, mew=0, color=C_RC, alpha=0.15, rasterized=True, zorder=2)
    bp = ax.boxplot(vals, positions=[xi], widths=0.55, patch_artist=True,
                    showfliers=False, whis=(5, 95), zorder=3,
                    medianprops=dict(color="black", lw=1.2),
                    whiskerprops=dict(lw=0.7, color="0.3"),
                    capprops=dict(lw=0.7, color="0.3"),
                    boxprops=dict(lw=0.6, edgecolor="0.15"))
    bp["boxes"][0].set_facecolor("0.55" if d == 0 else C_RC)
    bp["boxes"][0].set_alpha(0.75)
ax.set_yscale("log")
ax.set_xticks(range(len(ds)))
ax.set_xticklabels([str(d) for d in ds])
ax.set_xlabel("rechain distance $d$ (blocks)")
ax.set_ylabel("latency (µs)")
lo, hi = rec.verify_us.min(), rec.verify_us.max()
ax.set_ylim(lo * 0.55, hi * 3.2)
ax.yaxis.grid(True, **GRID)
ax.set_axisbelow(True)
ax.set_xlim(-0.65, len(ds) - 0.35)
m0 = rec.loc[rec.d == 0, "verify_us"].median()
ax.annotate("evML-DSA verify\n(no rechain, $d{=}0$)",
            xy=(0.30, m0), xytext=(0.9, m0 * 0.16), fontsize=5.6,
            color="0.25", ha="left", va="center",
            arrowprops=dict(arrowstyle="-", lw=0.45, color="0.45",
                            shrinkA=1, shrinkB=1))
ax.set_title("Verify latency vs. rechain distance", pad=3)

# --- (c) whole-archive verification time: median line + min-max band ---
ax = axes[2]
g = arc.groupby("n_records")["total_s"]
med = g.median()
ax.fill_between(med.index, g.min(), g.max(), color=C_EV, alpha=0.14, lw=0,
                zorder=2)
ax.plot(arc.n_records, arc.total_s, "o", color=C_EV, ms=2.0, alpha=0.55,
        zorder=3)
ax.plot(med.index, med.values, "-o", color=C_EV, lw=1.1, ms=2.4, zorder=4)
ax.set_xscale("log", base=2)
ax.set_yscale("log")
ticks = sorted(arc.n_records.unique())
ax.set_xticks(ticks)
ax.set_xticklabels([r"$2^{%d}$" % round(np.log2(t)) for t in ticks])
ax.minorticks_off()
ax.set_xlabel("archive size $n$ (records)")
ax.set_ylabel("total time (s)")
ax.set_ylim(arc.total_s.min() * 0.6, arc.total_s.max() * 2.4)
ax.yaxis.grid(True, **GRID)
ax.set_axisbelow(True)
ax.set_title("Whole-archive verification time", pad=3)

for a, lab in zip(axes, "abc"):
    p = a.get_position()
    fig.text(p.x0 - 0.055, p.y1 + 0.025, r"$\mathbf{%s}$" % lab,
             fontsize=9.5, va="top", ha="left")

fig.subplots_adjust(wspace=0.34, left=0.064, right=0.985, top=0.86,
                    bottom=0.185)
fig.savefig(OUT / "fig4.png")
fig.savefig(OUT / "fig4.pdf")
fig.savefig(OUT / "fig4.svg")
print("saved fig4")
