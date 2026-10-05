"""Gráficos del informe con matplotlib: SVG (claro y oscuro, con tooltips) para el HTML y PNG para el README.

Paleta: instancia de referencia validada (categórica en orden fijo, gris neutro para "antes"); el color nunca
es el único canal: cada serie lleva leyenda o etiqueta directa y cada gráfico tiene su tabla en el informe.
"""

from __future__ import annotations

import io
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure
from matplotlib.lines import Line2D

Mode = Literal["light", "dark"]

THEMES: dict[str, dict[str, str]] = {
    "light": {
        "surface": "#fcfcfb",
        "text": "#0b0b0b",
        "muted": "#52514e",
        "grid": "#e4e3df",
        "before": "#9a9993",
        "after": "#2a78d6",
        "s1": "#2a78d6",
        "s2": "#eb6834",
        "s3": "#1baf7a",
    },
    "dark": {
        "surface": "#1a1a19",
        "text": "#ffffff",
        "muted": "#c3c2b7",
        "grid": "#383835",
        "before": "#8a8983",
        "after": "#3987e5",
        "s1": "#3987e5",
        "s2": "#d95926",
        "s3": "#199e70",
    },
}


@dataclass
class Chart:
    name: str
    title: str
    svg: dict[str, str] = field(default_factory=dict)
    png: dict[str, bytes] = field(default_factory=dict)


@dataclass(frozen=True)
class Pair:
    label: str
    before: float | None
    after: float | None


@dataclass(frozen=True)
class Series:
    label: str
    values: list[float | None]


class _Tooltips:
    """Asigna un gid a cada marca y luego inserta <title> en el SVG (hover nativo del navegador)."""

    def __init__(self) -> None:
        self.texts: dict[str, str] = {}

    def tag(self, artist: object, text: str) -> None:
        gid = f"hlab-tip-{len(self.texts)}"
        artist.set_gid(gid)  # type: ignore[attr-defined]
        self.texts[gid] = text

    def inject(self, svg: str) -> str:
        for gid, text in self.texts.items():
            safe = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            svg = re.sub(rf'(<g id="{gid}"[^>]*>)', rf"\1<title>{safe}</title>", svg, count=1)
        return svg


def _style(ax: Axes, theme: dict[str, str]) -> None:
    ax.set_facecolor(theme["surface"])
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(theme["grid"])
    ax.tick_params(colors=theme["muted"], labelsize=9, length=0)
    ax.grid(axis="x", color=theme["grid"], linewidth=0.8)
    ax.set_axisbelow(True)


def _export(fig: Figure, tips: _Tooltips) -> tuple[str, bytes]:
    svg_buffer = io.StringIO()
    fig.savefig(svg_buffer, format="svg", bbox_inches="tight", facecolor=fig.get_facecolor())
    png_buffer = io.BytesIO()
    fig.savefig(png_buffer, format="png", dpi=160, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    svg = svg_buffer.getvalue()
    svg = svg[svg.find("<svg") :]
    return tips.inject(svg), png_buffer.getvalue()


def _fmt(value: float | None, unit: str) -> str:
    return "sin dato" if value is None else f"{value:.0f}{unit}"


def dumbbell(name: str, title: str, panels: Sequence[tuple[str, Sequence[Pair]]], unit: str = "") -> Chart:
    """Antes (gris) → después (azul) por host, en paneles pequeños con la misma escala 0-100."""
    chart = Chart(name=name, title=title)
    for mode in ("light", "dark"):
        theme = THEMES[mode]
        rows = max(len(pairs) for _, pairs in panels)
        fig, axes = plt.subplots(
            1, len(panels), figsize=(3.4 * len(panels), 0.55 * rows + 1.3), sharey=True, squeeze=False
        )
        fig.patch.set_facecolor(theme["surface"])
        tips = _Tooltips()
        for ax, (panel_title, pairs) in zip(axes[0], panels, strict=True):
            _style(ax, theme)
            ax.set_xlim(0, 100)
            ax.set_title(panel_title, color=theme["text"], fontsize=10, loc="left", pad=8)
            for y, pair in enumerate(pairs):
                if pair.before is not None and pair.after is not None:
                    ax.plot([pair.before, pair.after], [y, y], color=theme["grid"], linewidth=2, zorder=1)
                if pair.before is not None:
                    dot = ax.scatter(pair.before, y, s=70, color=theme["before"], zorder=2, linewidths=0)
                    tips.tag(dot, f"{panel_title} · {pair.label} · antes: {_fmt(pair.before, unit)}")
                if pair.after is not None:
                    dot = ax.scatter(
                        pair.after,
                        y,
                        s=70,
                        color=theme["after"],
                        zorder=3,
                        edgecolors=theme["surface"],
                        linewidths=2,
                    )
                    tips.tag(dot, f"{panel_title} · {pair.label} · después: {_fmt(pair.after, unit)}")
                    ax.annotate(
                        _fmt(pair.after, unit),
                        (pair.after, y),
                        xytext=(8, 0),
                        textcoords="offset points",
                        va="center",
                        fontsize=8.5,
                        color=theme["text"],
                    )
            ax.set_yticks(range(len(pairs)), [p.label for p in pairs])
            ax.set_ylim(-0.6, rows - 0.4)
            ax.invert_yaxis()
            ax.tick_params(axis="y", colors=theme["text"])
        handles = [
            Line2D([], [], marker="o", linestyle="", color=theme["before"], label="Antes (baseline)"),
            Line2D([], [], marker="o", linestyle="", color=theme["after"], label="Después (endurecido)"),
        ]
        fig.legend(
            handles=handles,
            loc="upper left",
            bbox_to_anchor=(0.0, 1.08),
            ncol=2,
            frameon=False,
            fontsize=9,
            labelcolor=theme["text"],
        )
        chart.svg[mode], chart.png[mode] = _export(fig, tips)
    return chart


def grouped_bars(
    name: str, title: str, categories: Sequence[str], before: Sequence[int], after: Sequence[int]
) -> Chart:
    """Conteos antes/después por categoría ordinal (severidad)."""
    chart = Chart(name=name, title=title)
    for mode in ("light", "dark"):
        theme = THEMES[mode]
        fig, ax = plt.subplots(figsize=(7.2, 3.0))
        fig.patch.set_facecolor(theme["surface"])
        _style(ax, theme)
        ax.grid(axis="x", visible=False)
        ax.grid(axis="y", color=theme["grid"], linewidth=0.8)
        tips = _Tooltips()
        width = 0.36
        xs = range(len(categories))
        for offset, values, color, label in (
            (-width / 2 - 0.02, before, theme["before"], "Antes"),
            (width / 2 + 0.02, after, theme["after"], "Después"),
        ):
            bars = ax.bar([x + offset for x in xs], values, width=width, color=color, label=label, linewidth=0)
            for bar, category, value in zip(bars, categories, values, strict=True):
                tips.tag(bar, f"{category} · {label.lower()}: {value} controles en fallo")
                ax.annotate(
                    str(value),
                    (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    fontsize=8.5,
                    color=theme["text"],
                )
        ax.set_xticks(list(xs), list(categories))
        ax.tick_params(axis="x", colors=theme["text"])
        ax.set_ylabel("controles × host en fallo", color=theme["muted"], fontsize=9)
        ax.legend(frameon=False, fontsize=9, labelcolor=theme["text"], loc="upper right")
        chart.svg[mode], chart.png[mode] = _export(fig, tips)
    return chart


def lines(name: str, title: str, x_labels: Sequence[str], series: Sequence[Series], unit: str = "%") -> Chart:
    """Evolución por host (máximo tres series: slots 1-3 de la paleta) con etiqueta directa al final."""
    chart = Chart(name=name, title=title)
    for mode in ("light", "dark"):
        theme = THEMES[mode]
        colors = [theme["s1"], theme["s2"], theme["s3"]]
        fig, ax = plt.subplots(figsize=(7.2, 3.2))
        fig.patch.set_facecolor(theme["surface"])
        _style(ax, theme)
        ax.grid(axis="x", visible=False)
        ax.grid(axis="y", color=theme["grid"], linewidth=0.8)
        ax.set_ylim(0, 105)
        tips = _Tooltips()
        xs = list(range(len(x_labels)))
        label_y = _spread([_last(serie.values) for serie in series[:3]], min_gap=7.0)
        for index, (color, serie) in enumerate(zip(colors, series[:3], strict=False)):
            points = [(x, v) for x, v in zip(xs, serie.values, strict=True) if v is not None]
            if not points:
                continue
            ax.plot([p[0] for p in points], [p[1] for p in points], color=color, linewidth=2, label=serie.label)
            for x, value in points:
                dot = ax.scatter(x, value, s=36, color=color, zorder=3, edgecolors=theme["surface"], linewidths=2)
                tips.tag(dot, f"{serie.label} · {x_labels[x]}: {value:.0f}{unit}")
            last_x, last_value = points[-1]
            ax.annotate(
                serie.label,
                (last_x, last_value),
                xytext=(last_x + 0.12, label_y[index] if label_y[index] is not None else last_value),
                textcoords="data",
                va="center",
                fontsize=8.5,
                color=theme["text"],
            )
        ax.set_xticks(xs, list(x_labels))
        ax.tick_params(axis="x", colors=theme["text"], labelsize=8)
        ax.set_ylabel(f"cumplimiento ({unit})", color=theme["muted"], fontsize=9)
        ax.set_xlim(-0.3, len(xs) - 0.2)
        ax.legend(frameon=False, fontsize=9, labelcolor=theme["text"], loc="lower right")
        chart.svg[mode], chart.png[mode] = _export(fig, tips)
    return chart


def _last(values: Sequence[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return present[-1] if present else None


def _spread(values: Sequence[float | None], min_gap: float) -> list[float | None]:
    """Separa verticalmente las etiquetas finales que quedarían encimadas (de arriba hacia abajo)."""
    order = sorted((i for i, v in enumerate(values) if v is not None), key=lambda i: values[i] or 0.0, reverse=True)
    placed: list[float | None] = list(values)
    previous: float | None = None
    for i in order:
        current = values[i] or 0.0
        if previous is not None and previous - current < min_gap:
            current = previous - min_gap
        placed[i] = current
        previous = current
    return placed


def save_png(chart: Chart, directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for mode, data in chart.png.items():
        suffix = "" if mode == "light" else "-dark"
        path = directory / f"{chart.name}{suffix}.png"
        path.write_bytes(data)
        written.append(path)
    return written
