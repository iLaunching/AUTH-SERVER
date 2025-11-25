"""Add OAuth fields to users table

Revision ID: add_oauth_fields
Revises: 
Create Date: 2025-11-25

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_oauth_fields'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Add OAuth provider fields to users table"""
    # Add oauth_provider column
    op.add_column('users', sa.Column('oauth_provider', sa.String(length=50), nullable=True))
    
    # Add oauth_provider_id column
    op.add_column('users', sa.Column('oauth_provider_id', sa.String(length=255), nullable=True))
    
    # Create index on oauth_provider for faster lookups
    op.create_index('ix_users_oauth_provider', 'users', ['oauth_provider'], unique=False)
    
    # Create composite index on oauth_provider and oauth_provider_id for uniqueness per provider
    op.create_index('ix_users_oauth_provider_id', 'users', ['oauth_provider', 'oauth_provider_id'], unique=False)


def downgrade():
    """Remove OAuth provider fields from users table"""
    # Drop indexes
    op.drop_index('ix_users_oauth_provider_id', table_name='users')
    op.drop_index('ix_users_oauth_provider', table_name='users')
    
    # Drop columns
    op.drop_column('users', 'oauth_provider_id')
    op.drop_column('users', 'oauth_provider')
