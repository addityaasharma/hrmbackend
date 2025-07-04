"""empty message

Revision ID: 7aecb95ad560
Revises: 2e73562649fd
Create Date: 2025-06-25 07:12:49.554214

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7aecb95ad560'
down_revision = '2e73562649fd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('adminleavename', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('adminleavename_ibfk_1'), type_='foreignkey')
        batch_op.create_foreign_key(None, 'superadminpanel', ['adminLeaveName'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('adminleavename', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key(batch_op.f('adminleavename_ibfk_1'), 'adminleavename', ['adminLeaveName'], ['id'])

    # ### end Alembic commands ###
