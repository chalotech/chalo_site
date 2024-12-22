"""initial migration

Revision ID: d94b20e9a2c0
Revises: 
Create Date: 2024-12-21 15:45:16.438041

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd94b20e9a2c0'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('purchase', schema=None) as batch_op:
        batch_op.add_column(sa.Column('payment_id', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('amount', sa.Float(), nullable=False))
        batch_op.add_column(sa.Column('currency', sa.String(length=3), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('purchase', schema=None) as batch_op:
        batch_op.drop_column('currency')
        batch_op.drop_column('amount')
        batch_op.drop_column('payment_id')

    # ### end Alembic commands ###