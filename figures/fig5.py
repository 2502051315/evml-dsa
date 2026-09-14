#!/usr/bin/env python3
"""Fig.5 final polish — targeted refinements to v3.
Changes: smaller (a)-(d) labels; panel (d) line lighter/thinner with dashed
segments; plain ML-DSA shown as hatched "n/a" placeholder slot in (d) with
footnote-style explanation; zero vs unavailable distinction in (b); slight
whitespace reduction."""
import csv, os, sys
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

mpl.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Nimbus Roman", "DejaVu Serif", "serif"],
    "svg.fonttype": "none", "pdf.fonttype": 42,
    "font.size": 7, "axes.labelsize": 6.5,
    "xtick.labelsize": 6, "ytick.labelsize": 5.5,
    "axes.titlesize": 6.5,
    "legend.fontsize": 5,
    "axes.spines.top": True, "axes.spines.right": True,
    "axes.linewidth": 0.5,
    "axes.grid": True, "grid.linestyle": "-",
    "grid.linewidth": 0.2, "grid.color": "0.93", "grid.alpha": 0.4,
    "xtick.direction": "in", "ytick.direction": "in",
    "xtick.major.size": 2, "ytick.major.size": 2,
    "xtick.major.width": 0.5, "ytick.major.width": 0.5,
    "xtick.top": True, "ytick.right": True,
    "legend.frameon": True, "legend.framealpha": 0.92,
    "legend.edgecolor": "0.85", "legend.fancybox": False,
    "legend.borderpad": 0.2, "legend.handlelength": 0.8,
    "legend.handletextpad": 0.3, "legend.labelspacing": 0.2,
    "legend.columnspacing": 0.5,
    "mathtext.fontset": "stix",
})

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "results", "fig5")
OUT = HERE

C_EV, C_PL, C_RE = "#3A6B9F", "#C49A3C", "#C48750"
C_LMS, C_XM, C_FRG = "#6B9E7A", "#8C8C8C", "#A0A0A0"
C_LINE = "#B05050"
HATCH = "///"

SCHEMES = ["evML", "plain", "rechain", "LMS", "XMSS", "FROG"]
SC_COLORS = [C_EV, C_PL, C_RE, C_LMS, C_XM, C_FRG]

def load(name):
    rows = {}
    with open(os.path.join(HERE, name)) as f:
        for r in csv.DictReader(f):
            rows[r["scheme"]] = r
    return rows

def key(name):
    for s in SCHEMES:
        if s.lower() in name.lower():
            return s
    return name

def gv(rows, scheme, col):
    for k, v in rows.items():
        if key(k) == scheme:
            val = v.get(col, "")
            return float(val) if val else None
    return None

def is_meas(rows, scheme):
    for k, v in rows.items():
        if key(k) == scheme:
            return v.get("source", "") == "measured"
    return False

def dash(ax, x, ylevel):
    """Subtle unavailable indicator: small en-dash."""
    ax.text(x, ylevel, "–", fontsize=5, color="0.72", ha="center",
            va="center", fontstyle="italic", zorder=5)

def main():
    base = load("fig5_cross_scheme.csv")
    stor = load("fig5_storage_footprint.csv")
    hist = load("fig5_historical_cost.csv")

    fig, axes = plt.subplots(1, 4, figsize=(7.0, 2.1))
    fig.subplots_adjust(left=0.062, right=0.92, top=0.82, bottom=0.30, wspace=0.48)
    xpos = np.arange(len(SCHEMES))
    bw = 0.32

    # ===== (a) Communication footprint =====
    ax = axes[0]
    for i, s in enumerate(SCHEMES):
        c = SC_COLORS[i]
        h = "" if is_meas(base, s) else HATCH
        sv = gv(base, s, "sig_B")
        pv = gv(base, s, "pk_B")
        if sv:
            ax.bar(i - bw/2, sv, bw*0.9, color=c, edgecolor="none", hatch=h, zorder=3)
        else:
            dash(ax, i - bw/2, 5000)
        if pv:
            ax.bar(i + bw/2, pv, bw*0.9, color=c, alpha=0.45, edgecolor="none", hatch=h, zorder=3)
        else:
            dash(ax, i + bw/2, 5000)
    ax.set_xticks(xpos); ax.set_xticklabels(SCHEMES, fontsize=5, rotation=0, ha="center")
    ax.set_yscale("log")
    ax.set_ylabel("bytes", labelpad=0.5)
    ax.set_title("Communication footprint", loc="left", fontstyle="italic", pad=3)
    ax.legend([plt.Rectangle((0,0),1,1,fc="0.4"), plt.Rectangle((0,0),1,1,fc="0.4",alpha=0.45)],
              ["sig", "pk"], fontsize=4.5, loc="upper right", ncol=2, columnspacing=0.5)

    # ===== (b) Signer-side storage footprint =====
    ax = axes[1]
    for i, s in enumerate(SCHEMES):
        c = SC_COLORS[i]
        h = "" if is_meas(stor, s) else HATCH
        sk = gv(stor, s, "secret_key_B")
        aux = gv(stor, s, "aux_state_B")
        if sk:
            ax.bar(i - bw/2, sk, bw*0.9, color=c, edgecolor="none", hatch=h, zorder=3)
        else:
            dash(ax, i - bw/2, 10000)
        if aux is not None and aux > 0:
            ax.bar(i + bw/2, aux, bw*0.9, color=c, alpha=0.45, edgecolor="none", hatch=h, zorder=3)
        elif aux is not None and aux == 0:
            ax.bar(i + bw/2, 1, bw*0.9, color=c, alpha=0.45, edgecolor="none", hatch=h, zorder=3)
            ax.text(i + bw/2, 1.4, "0", fontsize=4, color="0.55", ha="center", va="bottom")
        else:
            dash(ax, i + bw/2, 10000)
    ax.set_xticks(xpos); ax.set_xticklabels(SCHEMES, fontsize=5, rotation=0, ha="center")
    ax.set_yscale("log")
    ax.set_ylabel("bytes", labelpad=0.5)
    ax.set_title("Signer-side storage footprint", loc="left", fontstyle="italic", pad=3)
    ax.legend([plt.Rectangle((0,0),1,1,fc="0.4"), plt.Rectangle((0,0),1,1,fc="0.4",alpha=0.45)],
              ["sk", "state"], fontsize=4.5, loc="upper right", ncol=2, columnspacing=0.5)

    # ===== (c) Online computation =====
    ax = axes[2]
    for i, s in enumerate(SCHEMES):
        c = SC_COLORS[i]
        h = "" if is_meas(base, s) else HATCH
        sv = gv(base, s, "sign_us")
        vv = gv(base, s, "verify_us")
        if sv:
            ax.bar(i - bw/2, sv, bw*0.9, color=c, edgecolor="none", hatch=h, zorder=3)
        else:
            dash(ax, i - bw/2, 50000)
        if vv:
            ax.bar(i + bw/2, vv, bw*0.9, color=c, alpha=0.45, edgecolor="none", hatch=h, zorder=3)
        else:
            dash(ax, i + bw/2, 50000)
    ax.set_xticks(xpos); ax.set_xticklabels(SCHEMES, fontsize=5, rotation=0, ha="center")
    ax.set_yscale("log")
    ax.set_ylabel(r"$\mu$s", labelpad=0.5)
    ax.set_title("Online computation", loc="left", fontstyle="italic", pad=3)
    ax.legend([plt.Rectangle((0,0),1,1,fc="0.4"), plt.Rectangle((0,0),1,1,fc="0.4",alpha=0.45)],
              ["sign", "vfy"], fontsize=4.5, loc="upper right", ncol=2, columnspacing=0.5)

    # ===== (d) Historical-security cost =====
    ax = axes[3]
    ax2 = ax.twinx()
    # keep all 6 slots, plain shows as hatched "n/a" placeholder
    ev_vals = []
    hv_vals = []
    for i, s in enumerate(SCHEMES):
        c = SC_COLORS[i]
        ev = gv(hist, s, "hist_evidence_B")
        hv = gv(hist, s, "hist_verify_us")
        ev_vals.append(ev)
        hv_vals.append(hv)

        if s == "plain":
            # placeholder slot: hatched outline bar + "n/a" text
            ax.bar(i, 1, 0.5, facecolor="none", edgecolor=c, linewidth=0.5,
                   hatch="///", zorder=2, alpha=0.5)
            ax.text(i, 1.5, "n/a", fontsize=4.5, color="0.6", ha="center", va="bottom",
                    fontstyle="italic", zorder=5)
        elif ev:
            h = "" if is_meas(hist, s) else HATCH
            ax.bar(i, ev, 0.5, color=c, edgecolor="none", hatch=h, zorder=3, alpha=0.75)
        else:
            dash(ax, i, 2000)

    # lighter/thinner guide line across available points only
    lx = [i for i, hv in enumerate(hv_vals) if hv is not None]
    ly = [hv for hv in hv_vals if hv is not None]
    if lx:
        ax2.plot(lx, ly, "--", color=C_LINE, lw=0.6, zorder=4, alpha=0.7,
                 marker="o", mfc=C_LINE, mec="white", mew=0.4, markersize=3)

    ax.set_xticks(xpos)
    ax.set_xticklabels(SCHEMES, fontsize=5, rotation=0, ha="center")
    ax.set_yscale("log")
    ax2.set_yscale("log")
    ax.set_ylabel("evidence (bytes)", labelpad=0.5, color="0.25", fontsize=6)
    ax2.set_ylabel("verify ($\\mu$s)", labelpad=0.5, color=C_LINE, fontsize=6)
    ax.tick_params(axis="y", colors="0.25", labelsize=5.5)
    ax2.tick_params(axis="y", colors=C_LINE, labelsize=5.5)
    ax2.spines["right"].set_color(C_LINE)
    ax2.spines["right"].set_linewidth(0.5)
    ax2.spines["top"].set_visible(False)
    ax2.grid(False)
    ax.set_title("Historical-security cost", loc="left", fontstyle="italic", pad=3)
    handles = [plt.Rectangle((0,0),1,1,fc="0.4",alpha=0.75),
               Line2D([0],[0],marker="o",color=C_LINE,ls="--",ms=3,lw=0.6,alpha=0.7)]
    ax.legend(handles, ["evid", "vfy"], fontsize=4.5, loc="upper left", ncol=2, columnspacing=0.5)
    # footnote for plain omission
    ax.text(0.5, -0.44, "plain ML-DSA not FS; hist. cost undefined",
            transform=ax.transAxes, fontsize=3.8, color="0.6", ha="center", va="top",
            fontstyle="italic")

    # panel labels — smaller, lighter
    for ax_, lbl in zip(axes, ["(a)", "(b)", "(c)", "(d)"]):
        ax_.text(0.5, -0.36, lbl, transform=ax_.transAxes,
                 ha="center", va="top", fontsize=7, fontweight="normal", color="0.35")

    out = os.path.join(OUT, "fig5_comparison_summary_finalpolish")
    fig.savefig(out + ".png", dpi=600)
    fig.savefig(out + ".pdf")
    fig.savefig(out + ".svg")

    print("FINAL POLISH CHANGES:")
    print("  (a)-(d) labels: fontsize 8->7, color 0.35")
    print("  (b) title: 'Signer-side storage footprint' (full)")
    print("  (b) zero vs unavailable: '0' text for true zero; dash for unavailable")
    print("  (d) line: dashed, lw 0.6, alpha 0.7 (lighter guide line)")
    print("  (d) plain: hatched outline placeholder + 'n/a' + footnote")
    print("  (d) all 6 scheme slots present (consistent x-axis)")
    print("  whitespace: bottom margin 0.28->0.26, top 0.84->0.82")
    print("FIG5_FINALPOLISH_OK")

if __name__ == "__main__":
    sys.exit(main())
