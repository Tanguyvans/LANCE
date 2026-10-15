"""Read-only catalogue; launches use the existing validated pipeline API."""
from fastapi import APIRouter, Query

from src.agent.procedures import procedure_catalogue

router = APIRouter()


@router.get("")
def get_procedures():
    return procedure_catalogue()


@router.get("/runs")
def get_executions(procedure_id: str | None = Query(default=None, max_length=128),
                   target: str | None = Query(default=None, max_length=128),
                   include_diagnostics: bool = False,
                   offset: int = Query(default=0, ge=0), limit: int = Query(default=10, ge=1, le=50)):
    from src.api.procedure_runs import execution_page
    return execution_page(procedure_id=procedure_id, target=target,
                          include_diagnostics=include_diagnostics, offset=offset, limit=limit)


@router.get("/runs/{run_id}")
def get_execution(run_id: str):
    from src.api.procedure_runs import execution_summary
    return execution_summary(run_id)
