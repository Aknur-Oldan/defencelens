from alembic import op
import sqlalchemy as sa
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

def col(name, type_=sa.String(), nullable=False, **kw):
    return sa.Column(name, type_, nullable=nullable, **kw)
def idcol():
    return col("id", primary_key=True)
def fk(name, target):
    return sa.Column(name, sa.String(), sa.ForeignKey(target), nullable=False)

def upgrade():
    op.create_table("services", idcol(), col("name", unique=True), col("description", sa.Text()),
        col("importance", sa.Integer()), col("environment"), col("dependencies", sa.JSON()))
    op.create_table("sources", idcol(), col("name"), fk("service_id", "services.id"), col("kind"),
        col("last_received", nullable=True), col("accepted", sa.Integer()), col("duplicates", sa.Integer()),
        col("rejected", sa.Integer()), col("last_error", sa.Text(), nullable=True))
    op.create_table("events", idcol(), fk("source_id", "sources.id"), fk("service_id", "services.id"),
        col("dedup_key"), col("timestamp"), col("received_at"), col("data", sa.JSON()),
        sa.UniqueConstraint("source_id", "dedup_key"))
    for name in ("source_id", "service_id", "timestamp"):
        op.create_index("ix_events_"+name, "events", [name])
    op.create_table("incidents", idcol(), col("fingerprint", unique=True), fk("service_id", "services.id"),
        col("detector"), col("title"), col("priority"), col("status"), col("created_at"), col("updated_at"),
        col("evidence_ids", sa.JSON()), col("facts", sa.JSON()), col("hypotheses", sa.JSON()),
        col("limitations", sa.JSON()), col("recommendations", sa.JSON()))
    op.create_index("ix_incidents_service_id", "incidents", ["service_id"])
    op.create_table("actions", idcol(), fk("incident_id", "incidents.id"), col("timestamp"), col("actor"), col("kind"), col("note", sa.Text()))
    op.create_index("ix_actions_incident_id", "actions", ["incident_id"])
    op.create_table("scans", idcol(), col("filename"), col("digest"), col("status"), col("created_at"),
        col("updated_at"), col("error", sa.Text(), nullable=True), col("result", sa.JSON(), nullable=True))
    op.create_index("ix_scans_digest", "scans", ["digest"])
    op.create_table("deployments", idcol(), fk("service_id", "services.id"), fk("scan_id", "scans.id"),
        col("started_at"), col("ended_at", nullable=True), col("confirmation"), col("evidence", sa.Text()))

def downgrade():
    for table in ("deployments", "scans", "actions", "incidents", "events", "sources", "services"):
        op.drop_table(table)
