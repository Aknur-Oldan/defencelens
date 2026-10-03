from alembic import op
import sqlalchemy as sa
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("policies",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("max_critical", sa.Integer(), nullable=False),
        sa.Column("max_high", sa.Integer(), nullable=False),
        sa.Column("fail_on_secrets", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False))

def downgrade():
    op.drop_table("policies")
