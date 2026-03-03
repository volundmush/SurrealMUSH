from fastapi import APIRouter, Depends, HTTPException, status

from .boards import router as boards_router
from .channels import router as channels_router
from .factions import router as factions_router
from .pcs import router as pcs_router
from .themes import router as themes_router

router = APIRouter()
router.include_router(pcs_router, prefix="/pc")
router.include_router(boards_router, prefix="/board")
router.include_router(channels_router, prefix="/channel")
router.include_router(themes_router, prefix="/theme")
router.include_router(factions_router, prefix="/faction")
