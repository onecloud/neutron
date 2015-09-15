# Copyright 2015 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""Add ASR SNAT mapping table

Revision ID: 48af7eee8b1e
Revises: 3a6b3db996b6
Create Date: 2015-09-15 10:25:24.804957

"""

# revision identifiers, used by Alembic.
revision = '48af7eee8b1e'
down_revision = '3a6b3db996b6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('cisco_asr1k_snat_mapping',
        sa.Column('mapping_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('mapping_id'),
        mysql_engine='InnoDB',
    )


def downgrade():
    op.drop_table('cisco_asr1k_snat_mapping')
