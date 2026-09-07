"""add portal tables

Revision ID: e2f3a4b5c6d7
Revises: d4c1a8e37b62
Create Date: 2026-09-07

Native port of owui-auth-proxy/portal into Open WebUI's own database.
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = 'e2f3a4b5c6d7'
down_revision: Union[str, None] = 'd4c1a8e37b62'
branch_labels = None
depends_on = None


def _index_exists(inspector, index_name, table_name):
    return any(idx['name'] == index_name for idx in inspector.get_indexes(table_name))


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if 'portal_bot' not in tables:
        op.create_table(
            'portal_bot',
            sa.Column('id', sa.Text(), primary_key=True),
            sa.Column('public_id', sa.Text(), nullable=False),
            sa.Column('user_id', sa.Text(), nullable=False),
            sa.Column('name', sa.Text(), nullable=False),
            sa.Column('system_prompt', sa.Text(), nullable=False, server_default=''),
            sa.Column('greeting', sa.Text(), nullable=True),
            sa.Column('base_model_id', sa.Text(), nullable=False),
            sa.Column('owui_model_id', sa.Text(), nullable=True),
            sa.Column('allowed_origins', sa.JSON(), nullable=True),
            sa.Column('rate_limit_per_min', sa.Integer(), nullable=False, server_default='20'),
            sa.Column('status', sa.Text(), nullable=False, server_default='DRAFT'),
            sa.Column('last_error', sa.Text(), nullable=True),
            sa.Column('created_at', sa.BigInteger(), nullable=False),
            sa.Column('updated_at', sa.BigInteger(), nullable=False),
        )

    inspector.clear_cache()
    if 'portal_bot' in inspector.get_table_names():
        if not _index_exists(inspector, 'ix_portal_bot_public_id', 'portal_bot'):
            op.create_index('ix_portal_bot_public_id', 'portal_bot', ['public_id'], unique=True)
        if not _index_exists(inspector, 'ix_portal_bot_user_id', 'portal_bot'):
            op.create_index('ix_portal_bot_user_id', 'portal_bot', ['user_id'])

    if 'portal_chat_event' not in tables:
        op.create_table(
            'portal_chat_event',
            sa.Column('id', sa.Text(), primary_key=True),
            sa.Column('bot_id', sa.Text(), nullable=False),
            sa.Column('created_at', sa.BigInteger(), nullable=False),
            sa.Column('status', sa.Text(), nullable=False),
            sa.Column('ip_hash', sa.Text(), nullable=True),
            sa.Column('user_chars', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('turns', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('reply_chars', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('prompt_tokens', sa.Integer(), nullable=True),
            sa.Column('completion_tokens', sa.Integer(), nullable=True),
            sa.Column('total_tokens', sa.Integer(), nullable=True),
            sa.Column('latency_ms', sa.Integer(), nullable=True),
        )

    inspector.clear_cache()
    if 'portal_chat_event' in inspector.get_table_names():
        if not _index_exists(inspector, 'ix_portal_chat_event_bot_id', 'portal_chat_event'):
            op.create_index('ix_portal_chat_event_bot_id', 'portal_chat_event', ['bot_id'])
        if not _index_exists(inspector, 'ix_portal_chat_event_created_at', 'portal_chat_event'):
            op.create_index('ix_portal_chat_event_created_at', 'portal_chat_event', ['created_at'])


def downgrade():
    op.drop_index('ix_portal_chat_event_created_at', table_name='portal_chat_event')
    op.drop_index('ix_portal_chat_event_bot_id', table_name='portal_chat_event')
    op.drop_table('portal_chat_event')
    op.drop_index('ix_portal_bot_user_id', table_name='portal_bot')
    op.drop_index('ix_portal_bot_public_id', table_name='portal_bot')
    op.drop_table('portal_bot')
