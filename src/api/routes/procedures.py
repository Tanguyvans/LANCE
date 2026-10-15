"""Read-only catalogue; launches use the existing validated pipeline API."""
from fastapi import APIRouter

from src.agent.procedures import procedure_catalogue

router = APIRouter()


@router.get("")
def get_procedures():
    return procedure_catalogue()
