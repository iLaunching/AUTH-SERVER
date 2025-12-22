"""Add use_password field to users table

Revision ID: add_use_password
Revises: add_oauth_fields
Create Date: 2025-12-22

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_use_password'
down_revision = 'add_oauth_fields'
branch_labels = None
depends_on = None


def upgrade():
    """Add use_password field to users table"""
    # Add use_password column with default value true
    op.add_column('users', sa.Column('use_password', sa.Boolean(), nullable=False, server_default=sa.text('true')))


def downgrade():
    """Remove use_password field from users table"""
    # Drop column
    op.drop_column('users', 'use_password')
