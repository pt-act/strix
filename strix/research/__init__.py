"""Strix research apparatus — quarantined, NEVER part of the product DAG.

Everything under ``strix.research`` is measurement-only scaffolding for the propose-dispose
validation study (Spec B). It must never be imported by the product agent factory
(``strix.agents.factory``), the run entry (``strix.core.runner``), or the product interface
(``strix.interface``). In particular it hosts the **single-stage ablation mode** — the one
research baseline that lets a model self-confirm without the deterministic disposer — which is
a locus-1 failure if it ever reaches production. It is gated off by default and reachable only
via its own research entrypoint (``python -m strix.research.ablation``).
"""

from __future__ import annotations
