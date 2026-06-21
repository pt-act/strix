"""Inventory agent tools: collect, normalize, score, classify, spray, and persist."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from agents import RunContextWrapper, function_tool

from strix.core.inventory import (
    EndpointObservation,
    Param,
    build_ranked_map,
    classify_endpoint,
    collect_code,
    dedup_observations,
    extract_form_params,
    extract_js_params,
    extract_openapi_params,
    extract_proxy_params,
    load_ranked_map,
    save_ranked_map,
    spray_values_for_param,
)
from strix.core.inventory.parsers.reachability import annotate_reachability
from strix.core.proposals import (
    C1C8Answer,
    C1C8Checklist,
    InterventionFlags,
    assemble_proposal_context,
)
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from strix.core.inventory.models import ParamObservation


def _param_from_observation(obs: ParamObservation) -> Param:
    return Param(
        name=obs.name,
        location=obs.location,
        provenance=set(obs.provenance),
        example_values=set(obs.example_values),
    )


def _run_dir_from_ctx(ctx: RunContextWrapper) -> Path:
    """Return the run directory from the agent context."""
    context = cast("dict[str, Any] | None", getattr(ctx, "context", None))
    if isinstance(context, dict):
        run_dir = context.get("run_dir")
        if run_dir is not None:
            return Path(cast("str | Path", run_dir))
    raise RuntimeError("Tool context is missing 'run_dir'")


def _dump_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def collect_inventory_from_code(
    ctx: RunContextWrapper,
    source_path: str,
    target_id: str,
    base_url: str,
) -> str:
    """Collect attack-surface observations from a white-box code path (FastAPI only this phase)."""
    run_dir = _run_dir_from_ctx(ctx)
    observations = collect_code(Path(source_path), base_url=base_url)
    annotate_reachability(observations)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "observations": len(observations),
            "items": [_observation_to_json(obs) for obs in observations],
        },
    )


@function_tool(timeout=60, strict_mode=False)
async def collect_inventory_from_proxy(
    ctx: RunContextWrapper,
    records: list[dict[str, Any]],
    target_id: str,
) -> str:
    """Collect attack-surface observations from proxy request/response records."""
    run_dir = _run_dir_from_ctx(ctx)
    params = extract_proxy_params(records)
    # Proxy records alone don't give a single endpoint; return extracted params.
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "params": {name: param.model_dump() for name, param in params.items()},
        },
    )


@function_tool(timeout=60, strict_mode=False)
async def build_ranked_surface_map(
    ctx: RunContextWrapper,
    observations: list[dict[str, Any]],
    target_id: str,
) -> str:
    """Normalize, dedup, and score a list of EndpointObservation dicts into a ranked map."""
    run_dir = _run_dir_from_ctx(ctx)
    obs_list = [EndpointObservation.model_validate(obs) for obs in observations]
    endpoints = dedup_observations(obs_list)
    ranked = build_ranked_map(target_id, endpoints)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "endpoints": len(ranked.endpoints),
            "path": str(path),
        },
    )


@function_tool(timeout=60)
async def load_ranked_surface_map(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Load a previously saved ranked surface map."""
    run_dir = _run_dir_from_ctx(ctx)
    ranked = load_ranked_map(run_dir, target_id)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "endpoints": len(ranked.endpoints),
            "map": ranked.model_dump(),
        },
    )


@function_tool(timeout=60)
async def classify_inventory_params(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Classify every parameter on the saved ranked surface map and re-persist."""
    run_dir = _run_dir_from_ctx(ctx)
    ranked = load_ranked_map(run_dir, target_id)
    for endpoint in ranked.endpoints.values():
        classify_endpoint(endpoint)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "endpoints": len(ranked.endpoints),
            "path": str(path),
        },
    )


@function_tool(timeout=60, strict_mode=False)
async def spray_inventory_params(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Return deterministic spray values for every classified parameter on the map."""
    run_dir = _run_dir_from_ctx(ctx)
    ranked = load_ranked_map(run_dir, target_id)
    spray_plan: dict[str, dict[str, list[str]]] = {}
    for key, endpoint in ranked.endpoints.items():
        spray_plan[key] = {
            param.name: spray_values_for_param(param)
            for param in endpoint.params.values()
            if param.class_evidence is not None
        }
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "spray_plan": spray_plan,
        },
    )


def _merge_extracted_into_endpoints(
    endpoints: dict[str, Any],
    extracted: dict[str, ParamObservation],
) -> None:
    for name, obs in extracted.items():
        for endpoint in endpoints.values():
            if name in endpoint.params:
                existing = endpoint.params[name]
                existing.provenance |= set(obs.provenance)
                existing.example_values |= set(obs.example_values)
            else:
                endpoint.params[name] = _param_from_observation(obs)


@function_tool(timeout=60, strict_mode=False)
async def enrich_inventory_from_openapi(
    ctx: RunContextWrapper,
    spec: dict[str, Any],
    target_id: str,
) -> str:
    """Extract parameter candidates from an OpenAPI spec and merge into the saved map."""
    run_dir = _run_dir_from_ctx(ctx)
    extracted = extract_openapi_params(spec)
    ranked = load_ranked_map(run_dir, target_id)
    _merge_extracted_into_endpoints(ranked.endpoints, extracted)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "extracted_params": len(extracted),
            "path": str(path),
        },
    )


@function_tool(timeout=60)
async def enrich_inventory_from_js(
    ctx: RunContextWrapper,
    source: str,
    target_id: str,
) -> str:
    """Extract parameter candidates from JS source and merge into the saved map."""
    run_dir = _run_dir_from_ctx(ctx)
    extracted = extract_js_params(source)
    ranked = load_ranked_map(run_dir, target_id)
    _merge_extracted_into_endpoints(ranked.endpoints, extracted)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "extracted_params": len(extracted),
            "path": str(path),
        },
    )


@function_tool(timeout=60)
async def enrich_inventory_from_forms(
    ctx: RunContextWrapper,
    html: str,
    target_id: str,
) -> str:
    """Extract parameter candidates from HTML forms and merge into the saved map."""
    run_dir = _run_dir_from_ctx(ctx)
    extracted = extract_form_params(html)
    ranked = load_ranked_map(run_dir, target_id)
    _merge_extracted_into_endpoints(ranked.endpoints, extracted)
    path = save_ranked_map(run_dir, ranked)
    return _dump_json(
        {
            "success": True,
            "target_id": target_id,
            "run_dir": str(run_dir),
            "extracted_params": len(extracted),
            "path": str(path),
        },
    )


def _build_c1c8_checklist(answers: list[dict[str, str]] | None) -> C1C8Checklist | None:
    """Turn a list of answer dicts into a C1C8 checklist.

    Each answer dict may contain ``question_id`` (e.g. C3/C5/C6/C7),
    ``answer`` (yes/no/unknown/na), and an optional ``rationale``.
    """
    if not answers:
        return None
    questions = {q.split()[0].rstrip(":"): q for q in C1C8Checklist.default_questions()}
    checklist = C1C8Checklist()
    for answer in answers:
        question_id = answer.get("question_id", "")
        if question_id not in questions:
            continue
        checklist.answers.append(
            C1C8Answer(
                question_id=question_id,
                question=questions[question_id],
                answer=answer.get("answer", "unknown"),  # type: ignore[arg-type]
                rationale=answer.get("rationale"),
            )
        )
    return checklist


@function_tool(timeout=60, strict_mode=False)
async def propose_vulnerability_investigation(
    ctx: RunContextWrapper,
    target_id: str,
    endpoint_key: str,
    param_name: str | None = None,
    cwe: str | None = None,
    control_path: bool = False,
    knowledge_path: bool = False,
    c1_c8_checklist: bool = False,
    c1_c8_answers: list[dict[str, str]] | None = None,
    harnesses_selected: list[str] | None = None,
) -> str:
    """Assemble proposal-time context and record the proposal in the funnel.

    This tool is proposal-stage only. It does not run any harness and does
    not set ``evidence_class``. It records the active intervention flags and
    the supplied context so the downstream disposer can later attach its
    verdict to the same proposal record.

    C1-C8 self-interrogation questions (pass ``question_id`` in answers):

    - C3: does the endpoint rely on another component or downstream service
      to enforce a security check?
    - C5: does the bug require a specific prior state or multi-step sequence?
    - C6: can a race condition or TOCTOU alter the outcome?
    - C7: does a parameter cross a trust boundary?

    Args:
        target_id: Target identifier used to load the ranked surface map.
        endpoint_key: Key of the endpoint to propose investigating.
        param_name: Optional parameter name to focus on.
        cwe: CWE the agent suspects (e.g. CWE-639).
        control_path: Enable Control-Path verbalization.
        knowledge_path: Enable Knowledge-Path CWE priors.
        c1_c8_checklist: Enable the C1-C8 self-interrogation checklist.
        c1_c8_answers: Agent answers to the enabled checklist questions.
        harnesses_selected: Harnesses the agent intends to run.
    """
    run_dir = _run_dir_from_ctx(ctx)
    ranked = load_ranked_map(run_dir, target_id)
    endpoint = ranked.endpoints.get(endpoint_key)
    if endpoint is None:
        return _dump_json({"success": False, "error": f"Endpoint not found: {endpoint_key!r}"})

    param = endpoint.params.get(param_name) if param_name else None

    flags = InterventionFlags(
        control_path=control_path,
        knowledge_path=knowledge_path,
        c1_c8_checklist=c1_c8_checklist,
    )
    checklist: C1C8Checklist | None = None
    if c1_c8_checklist:
        checklist = _build_c1c8_checklist(c1_c8_answers) or C1C8Checklist()

    context = assemble_proposal_context(endpoint, param, flags, checklist)

    c1_c8_answers_dict: dict[str, C1C8Answer] = {}
    if checklist is not None:
        c1_c8_answers_dict = {a.question_id: a for a in checklist.answers}

    report_state = get_global_report_state()
    proposal_id: str | None = None
    if report_state is not None:
        record = report_state.funnel_log.start_proposal(
            engagement_id=target_id,
            endpoint_key=endpoint_key,
            param_name=param_name,
            cwe=cwe,
            c1_c8_answers=c1_c8_answers_dict,
            active_interventions=flags,
            harnesses_selected=list(harnesses_selected or []),
            supplied_context=context,
        )
        proposal_id = record.proposal_id
        report_state.save_run_data()

    return _dump_json(
        {
            "success": True,
            "proposal_id": proposal_id,
            "endpoint_key": endpoint_key,
            "param_name": param_name,
            "cwe": cwe,
            "active_flags": context.active_flags.model_dump(),
            "control_path_nl": context.control_path_nl,
            "knowledge_path_nl": context.knowledge_path_nl,
            "c1_c8_checklist": checklist.model_dump() if checklist else None,
            "c1_c8_questions": C1C8Checklist.default_questions() if c1_c8_checklist else None,
            "warning": (
                "Proposal context returned but not recorded: no global report state available."
                if report_state is None
                else None
            ),
        }
    )


def _observation_to_json(obs: EndpointObservation) -> dict[str, Any]:
    return obs.model_dump()
