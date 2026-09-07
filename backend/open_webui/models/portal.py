"""
Portal (Chatbot-as-a-Service) data layer.

Native port of ``owui-auth-proxy/portal`` (previously an Express + Prisma app
with its own Postgres database). Here it lives inside Open WebUI's own DB and
reuses Open WebUI auth. A "bot" is just *base model + system prompt*; on save it
provisions a workspace ``Model`` row (id ``portal-<public_id>``). Anonymous site
visitors chat through ``/portal/w/<public_id>`` + ``/api/portal/public/<public_id>/chat``.

Tables:
    portal_bot          one row per bot
    portal_chat_event   one row per public widget chat request (counters only,
                        no message text, salted+truncated IP hash)
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from open_webui.internal.db import Base, get_async_db_context
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    BigInteger,
    Column,
    Integer,
    JSON,
    Text,
    delete,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

DEFAULT_GREETING = 'היי! איך ניתן לעזור לך?'

BOT_STATUS_DRAFT = 'DRAFT'
BOT_STATUS_READY = 'READY'
BOT_STATUS_ERROR = 'ERROR'


####################
# DB schema
####################


class PortalBot(Base):
    __tablename__ = 'portal_bot'

    id = Column(Text, primary_key=True, unique=True)
    # Opaque id used in the public iframe URL - not the db id, not the model id.
    public_id = Column(Text, unique=True, index=True)
    user_id = Column(Text, index=True)  # owner (Open WebUI user id)

    name = Column(Text)
    system_prompt = Column(Text, default='')
    greeting = Column(Text, default=DEFAULT_GREETING)
    base_model_id = Column(Text)

    # Set once the portal provisions the workspace model. Never sent to the widget.
    owui_model_id = Column(Text, nullable=True)

    allowed_origins = Column(JSON, nullable=True)  # list[str] of bare http(s) origins
    rate_limit_per_min = Column(Integer, default=20)

    status = Column(Text, default=BOT_STATUS_DRAFT)  # DRAFT | READY | ERROR
    last_error = Column(Text, nullable=True)

    created_at = Column(BigInteger)  # epoch seconds
    updated_at = Column(BigInteger)  # epoch seconds


class PortalChatEvent(Base):
    __tablename__ = 'portal_chat_event'

    id = Column(Text, primary_key=True, unique=True)
    bot_id = Column(Text, index=True)
    created_at = Column(BigInteger, index=True)  # epoch seconds

    # ok | error | rate_limited | bad_request | blocked | unavailable
    status = Column(Text)
    ip_hash = Column(Text)  # sha256(ip + secret)[:16] - never a raw IP

    user_chars = Column(Integer, default=0)
    turns = Column(Integer, default=0)
    reply_chars = Column(Integer, default=0)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)
    latency_ms = Column(Integer, nullable=True)


####################
# Pydantic models
####################


class PortalBotModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    public_id: str
    user_id: str
    name: str
    system_prompt: str = ''
    greeting: str = DEFAULT_GREETING
    base_model_id: str
    owui_model_id: Optional[str] = None
    allowed_origins: list[str] = Field(default_factory=list)
    rate_limit_per_min: int = 20
    status: str = BOT_STATUS_DRAFT
    last_error: Optional[str] = None
    created_at: int
    updated_at: int


class PortalBotForm(BaseModel):
    name: str
    base_model_id: str
    system_prompt: str = ''
    greeting: str = DEFAULT_GREETING
    allowed_origins: list[str] = Field(default_factory=list)
    rate_limit_per_min: int = 20


class PortalBotUpdateForm(BaseModel):
    name: Optional[str] = None
    base_model_id: Optional[str] = None
    system_prompt: Optional[str] = None
    greeting: Optional[str] = None
    allowed_origins: Optional[list[str]] = None
    rate_limit_per_min: Optional[int] = None


####################
# Table classes
####################


class PortalBotsTable:
    async def insert(
        self, user_id: str, form: PortalBotForm, db: Optional[AsyncSession] = None
    ) -> Optional[PortalBotModel]:
        async with get_async_db_context(db) as db:
            now = int(time.time())
            bot = PortalBot(
                id=str(uuid.uuid4()),
                public_id=uuid.uuid4().hex,
                user_id=user_id,
                name=form.name,
                system_prompt=(form.system_prompt or '')[:8000],
                greeting=(form.greeting or DEFAULT_GREETING)[:500],
                base_model_id=form.base_model_id,
                owui_model_id=None,
                allowed_origins=list(form.allowed_origins or []),
                rate_limit_per_min=_clamp_rate(form.rate_limit_per_min),
                status=BOT_STATUS_DRAFT,
                last_error=None,
                created_at=now,
                updated_at=now,
            )
            db.add(bot)
            await db.commit()
            await db.refresh(bot)
            return PortalBotModel.model_validate(bot)

    async def get_by_id(self, bot_id: str, db: Optional[AsyncSession] = None) -> Optional[PortalBotModel]:
        async with get_async_db_context(db) as db:
            row = (await db.execute(select(PortalBot).where(PortalBot.id == bot_id))).scalars().first()
            return PortalBotModel.model_validate(row) if row else None

    async def get_by_public_id(
        self, public_id: str, db: Optional[AsyncSession] = None
    ) -> Optional[PortalBotModel]:
        async with get_async_db_context(db) as db:
            row = (
                (await db.execute(select(PortalBot).where(PortalBot.public_id == public_id)))
                .scalars()
                .first()
            )
            return PortalBotModel.model_validate(row) if row else None

    async def get_by_owner(self, user_id: str, db: Optional[AsyncSession] = None) -> list[PortalBotModel]:
        async with get_async_db_context(db) as db:
            rows = (
                (
                    await db.execute(
                        select(PortalBot)
                        .where(PortalBot.user_id == user_id)
                        .order_by(PortalBot.created_at.desc())
                    )
                )
                .scalars()
                .all()
            )
            return [PortalBotModel.model_validate(r) for r in rows]

    async def get_all(self, db: Optional[AsyncSession] = None) -> list[PortalBotModel]:
        async with get_async_db_context(db) as db:
            rows = (
                (await db.execute(select(PortalBot).order_by(PortalBot.created_at.desc()))).scalars().all()
            )
            return [PortalBotModel.model_validate(r) for r in rows]

    async def update(
        self, bot_id: str, fields: dict, db: Optional[AsyncSession] = None
    ) -> Optional[PortalBotModel]:
        async with get_async_db_context(db) as db:
            row = (await db.execute(select(PortalBot).where(PortalBot.id == bot_id))).scalars().first()
            if not row:
                return None
            for k, v in fields.items():
                setattr(row, k, v)
            row.updated_at = int(time.time())
            await db.commit()
            await db.refresh(row)
            return PortalBotModel.model_validate(row)

    async def delete(self, bot_id: str, db: Optional[AsyncSession] = None) -> bool:
        async with get_async_db_context(db) as db:
            await db.execute(delete(PortalChatEvent).where(PortalChatEvent.bot_id == bot_id))
            await db.execute(delete(PortalBot).where(PortalBot.id == bot_id))
            await db.commit()
            return True


class PortalChatEventsTable:
    async def record(self, bot_id: str, status: str, fields: dict, db: Optional[AsyncSession] = None) -> None:
        try:
            async with get_async_db_context(db) as db:
                db.add(
                    PortalChatEvent(
                        id=str(uuid.uuid4()),
                        bot_id=bot_id,
                        created_at=int(time.time()),
                        status=status,
                        ip_hash=fields.get('ip_hash', ''),
                        user_chars=int(fields.get('user_chars', 0) or 0),
                        turns=int(fields.get('turns', 0) or 0),
                        reply_chars=int(fields.get('reply_chars', 0) or 0),
                        prompt_tokens=_num_or_none(fields.get('prompt_tokens')),
                        completion_tokens=_num_or_none(fields.get('completion_tokens')),
                        total_tokens=_num_or_none(fields.get('total_tokens')),
                        latency_ms=_num_or_none(fields.get('latency_ms')),
                    )
                )
                await db.commit()
        except Exception as e:  # analytics write must never break the response
            log.error('portal chatEvent log failed: %s', e)

    async def compute_stats(
        self,
        bot_ids: list[str],
        days: int = 30,
        include_recent: bool = False,
        db: Optional[AsyncSession] = None,
    ) -> dict:
        d = min(90, max(1, int(days or 30)))
        since = int(time.time()) - d * 86400

        if not bot_ids:
            return _empty_stats(d, since)

        async with get_async_db_context(db) as db:
            rows = (
                (
                    await db.execute(
                        select(PortalChatEvent).where(
                            PortalChatEvent.bot_id.in_(bot_ids),
                            PortalChatEvent.created_at >= since,
                        )
                    )
                )
                .scalars()
                .all()
            )

            bots = (
                (await db.execute(select(PortalBot).where(PortalBot.id.in_(bot_ids)))).scalars().all()
            )
            bot_meta = {b.id: b for b in bots}

        # daily buckets
        buckets: dict[str, dict] = {}
        for i in range(d):
            key = _day_key(since + i * 86400)
            buckets[key] = {'date': key, 'messages': 0, 'tokens': 0}
        for r in rows:
            key = _day_key(r.created_at)
            if key in buckets:
                buckets[key]['messages'] += 1
                buckets[key]['tokens'] += r.completion_tokens or 0
        daily = list(buckets.values())

        status_map: dict[str, int] = {}
        per_bot: dict[str, dict] = {}
        unique_ips = set()
        total_reply_chars = total_user_chars = total_tokens = 0
        latencies: list[int] = []

        for r in rows:
            status_map[r.status] = status_map.get(r.status, 0) + 1
            total_reply_chars += r.reply_chars or 0
            total_user_chars += r.user_chars or 0
            total_tokens += r.completion_tokens or 0
            if r.latency_ms is not None:
                latencies.append(r.latency_ms)
            if r.ip_hash:
                unique_ips.add(r.ip_hash)
            pb = per_bot.setdefault(
                r.bot_id, {'id': r.bot_id, 'messages': 0, 'tokens': 0, 'reply_chars': 0, 'last_at': 0}
            )
            pb['messages'] += 1
            pb['tokens'] += r.completion_tokens or 0
            pb['reply_chars'] += r.reply_chars or 0
            pb['last_at'] = max(pb['last_at'], r.created_at)

        for bid, pb in per_bot.items():
            meta = bot_meta.get(bid)
            pb['name'] = meta.name if meta else bid
            pb['status'] = meta.status if meta else None

        out = {
            'range': {'days': d, 'since': since},
            'totals': {
                'messages': len(rows),
                'ok': status_map.get('ok', 0),
                'errors': status_map.get('error', 0),
                'rateLimited': status_map.get('rate_limited', 0),
                'blocked': status_map.get('blocked', 0),
                'badRequest': status_map.get('bad_request', 0),
                'unavailable': status_map.get('unavailable', 0),
                'replyChars': total_reply_chars,
                'userChars': total_user_chars,
                'tokens': total_tokens,
                'avgLatencyMs': round(sum(latencies) / len(latencies)) if latencies else 0,
                'uniqueVisitors': len(unique_ips),
            },
            'statusBreakdown': status_map,
            'daily': daily,
            'bots': sorted(per_bot.values(), key=lambda x: x['messages'], reverse=True),
        }

        if include_recent:
            recent = sorted(rows, key=lambda r: r.created_at, reverse=True)[:25]
            out['recent'] = [
                {
                    'createdAt': r.created_at,
                    'status': r.status,
                    'turns': r.turns,
                    'userChars': r.user_chars,
                    'replyChars': r.reply_chars,
                    'genTokens': r.completion_tokens,
                    'latencyMs': r.latency_ms,
                    'botId': r.bot_id,
                }
                for r in recent
            ]

        return out


####################
# helpers
####################


def _clamp_rate(v) -> int:
    try:
        return max(1, min(600, int(v)))
    except (TypeError, ValueError):
        return 20


def _num_or_none(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _day_key(epoch_seconds: int) -> str:
    return time.strftime('%Y-%m-%d', time.gmtime(epoch_seconds))


def _empty_stats(days: int, since: int) -> dict:
    return {
        'range': {'days': days, 'since': since},
        'totals': {
            'messages': 0, 'ok': 0, 'errors': 0, 'rateLimited': 0, 'blocked': 0,
            'badRequest': 0, 'unavailable': 0, 'replyChars': 0, 'userChars': 0,
            'tokens': 0, 'avgLatencyMs': 0, 'uniqueVisitors': 0,
        },
        'statusBreakdown': {},
        'daily': [
            {'date': _day_key(since + i * 86400), 'messages': 0, 'tokens': 0} for i in range(days)
        ],
        'bots': [],
    }


PortalBots = PortalBotsTable()
PortalChatEvents = PortalChatEventsTable()
