# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import re
import textwrap
from os.path import expanduser

import yaml

from clusterdock.models import Cluster, Node
from clusterdock.utils import wait_for_condition

logger = logging.getLogger('clusterdock.{}'.format(__name__))

DEFAULT_NAMESPACE = 'clusterdock'
DEFAULT_OPERATING_SYSTEM = 'centos6.8'

KDC_ACL_FILEPATH = '/var/kerberos/krb5kdc/kadm5.acl'
KDC_CONF_FILEPATH = '/var/kerberos/krb5kdc/kdc.conf'
KERBEROS_VOLUME_DIR = '/etc/clusterdock/kerberos'
KDC_KEYTAB_FILENAME = 'clusterdock.keytab'
KDC_USER_KEYTAB_FILEPATH = '{}/{}'.format(KERBEROS_VOLUME_DIR, KDC_KEYTAB_FILENAME)
KDC_KRB5_CONF_FILEPATH = '/etc/krb5.conf'

DSE_HOME_DIR = '/etc/dse'
DSE_CONF_FILENAME = 'dse.yaml'
DSE_CONF_FILEPATH = '{}/{}'.format(DSE_HOME_DIR, DSE_CONF_FILENAME)
DSE_CASSANDRA_CONF_FILENAME = 'cassandra.yaml'
DSE_CASSANDRA_CONF_FILEPATH = '{}/cassandra/{}'.format(DSE_HOME_DIR, DSE_CASSANDRA_CONF_FILENAME)
DSE_CQLSH_FILEPATH = '/usr/bin/cqlsh'
DSE_CQLSHRC_HOME_DIR = '/root/.cassandra'
DSE_CQLSHRC_FILEPATH = '{}/cqlshrc'.format(DSE_CQLSHRC_HOME_DIR)
DSE_KEYTAB_FILEPATH = '{}/dse.keytab'.format(DSE_HOME_DIR)
DSE_USER_KEYTAB_FILEPATH = '{}/{}'.format(DSE_HOME_DIR, KDC_KEYTAB_FILENAME)


def main(args):
    global quiet_logging
    quiet_logging = False if args.verbose else True
    dse_image = '{}/{}/clusterdock:dse{}'.format(args.registry, args.namespace, args.dse_version)

    if args.kerberos:
        _setup_kerberos_nodes(args, dse_image)
    else:
        _setup_non_kerberos_nodes(args, dse_image)


def _setup_non_kerberos_nodes(args, dse_image):
    nodes = [Node(hostname=hostname, group='nodes', image=dse_image) for hostname in args.nodes]
    cluster = Cluster(*nodes)
    cluster.start(args.network)

    # DSE node logic
    logger.info('Updating DSE configurations and starting DSE nodes ...')
    cluster_name = args.dse_cluster_name
    cluster_seeds = ','.join(node.ip_address for node in nodes)
    for node in nodes:
        # DSE config specific commands
        dse_config_commands = [
            'cp {} {}.org'.format(DSE_CASSANDRA_CONF_FILEPATH, DSE_CASSANDRA_CONF_FILEPATH),
            'cp {} {}.org'.format(DSE_CONF_FILEPATH, DSE_CONF_FILEPATH),
            'mkdir -p {}'.format(DSE_CQLSHRC_HOME_DIR)
        ]
        node.execute(command="bash -c '{}'".format('; '.join(dse_config_commands)), quiet=quiet_logging)
        # DSE cassandra.yaml mods
        cassandra_config_data = yaml.load(node.get_file(DSE_CASSANDRA_CONF_FILEPATH))
        cassandra_config_data['cluster_name'] = cluster_name
        cassandra_config_data['listen_address'] = node.ip_address
        cassandra_config_data['rpc_address'] = node.ip_address
        cassandra_config_data['seed_provider'][0]['parameters'][0]['seeds'] = cluster_seeds
        node.put_file(DSE_CASSANDRA_CONF_FILEPATH, yaml.dump(cassandra_config_data))
        # DSE dse.yaml mods
        dse_config_data = yaml.load(node.get_file(DSE_CONF_FILEPATH))
        dse_config_data['audit_logging_options']['enabled'] = True
        dse_config_data['authentication_options'] = {'enabled': True, 'default_scheme': 'internal'}
        node.put_file(DSE_CONF_FILEPATH, yaml.dump(dse_config_data))
        # DSE cqlsh specific commands
        cqlsh_cmd_data = node.get_file(DSE_CQLSH_FILEPATH)
        node.put_file(DSE_CQLSH_FILEPATH, re.sub(r'.*(bash code here).*', '. /opt/rh/python27/enable', cqlsh_cmd_data))
        node.execute(command='chmod +x {}'.format(DSE_CQLSH_FILEPATH), quiet=quiet_logging)
        cqlshrc_data = """
            [connection]
            hostname = {}
            port = 9042
        """.format(node.fqdn)
        node.put_file(DSE_CQLSHRC_FILEPATH, textwrap.dedent(cqlshrc_data))
        # start DSE on the node
        node.execute('service dse restart')

    logger.info('Validating DSE service health ...')
    cqlsh_cmd = "cqlsh -u cassandra -p cassandra {} --debug -e 'DESCRIBE KEYSPACES'".format(nodes[0].fqdn)
    _validate_dse_health(nodes=nodes, node_cmd=cqlsh_cmd, node_cmd_expected='system_schema')

    logger.info('DSE cluster is available and its contacts are: {}'.format(','.join(node.fqdn for node in nodes)))
    logger.info('From its node, DSE can be accessed with: cqlsh -u cassandra -p cassandra')


def _setup_kerberos_nodes(args, dse_image):
    kerberos_volume_dir = args.kerberos_config_directory.replace('~', expanduser('~'))

    nodes = [Node(hostname=hostname, group='nodes', image=dse_image,
                  volumes=[{kerberos_volume_dir: KERBEROS_VOLUME_DIR}]) for hostname in args.nodes]

    kdc_image = '{}/{}/topology_nodebase_kerberos:{}'.format(args.registry, args.namespace or DEFAULT_NAMESPACE,
                                                             args.operating_system or DEFAULT_OPERATING_SYSTEM)
    kdc_hostname = args.kdc_node[0]
    kdc_node = Node(hostname=kdc_hostname, group='kdc', image=kdc_image,
                    volumes=[{kerberos_volume_dir: KERBEROS_VOLUME_DIR}])
    cluster = Cluster(kdc_node, *nodes)
    cluster.start(args.network)

    logger.info('Updating KDC configurations ...')
    realm = cluster.network.upper()
    # Update configurations
    krb5_conf_data = kdc_node.get_file(KDC_KRB5_CONF_FILEPATH)
    kdc_node.put_file(KDC_KRB5_CONF_FILEPATH,
                      re.sub(r'EXAMPLE.COM', realm,
                             re.sub(r'example.com', cluster.network,
                                    re.sub(r'kerberos.example.com', r'{}.{}'.format(kdc_hostname, cluster.network),
                                           krb5_conf_data))))
    kdc_conf_data = kdc_node.get_file(KDC_CONF_FILEPATH)
    kdc_node.put_file(KDC_CONF_FILEPATH,
                      re.sub(r'EXAMPLE.COM', realm,
                             kdc_conf_data.replace(r'[kdcdefaults]',
                                                   '[kdcdefaults]\n max_renewablelife = 7d\n max_life = 1d')))
    acl_data = kdc_node.get_file(KDC_ACL_FILEPATH)
    kdc_node.put_file(KDC_ACL_FILEPATH, re.sub(r'EXAMPLE.COM', realm, acl_data))

    kdc_commands = [
        'kdb5_util create -s -r {realm} -P kdcadmin'.format(realm=realm),
        'kadmin.local -q "addprinc -pw {adminpw} admin/admin@{realm}"'.format(adminpw='acladmin', realm=realm)
    ]

    logger.info('Starting KDC ...')
    # Add the following commands before starting kadmin daemon etc.
    if args.kerberos_principals:
        principal_list = ['{}@{}'.format(primary, realm) for primary in args.kerberos_principals.split(',')]
        create_principals_cmds = ['kadmin.local -q "addprinc -randkey {}"'.format(principal)
                                  for principal in principal_list]
        kdc_commands.extend(create_principals_cmds)

        kdc_commands.append('sleep 2') # sleep few seconds to have Docker volume available
        kdc_commands.append('rm -f {}'.format(KDC_USER_KEYTAB_FILEPATH))
        create_keytab_cmd = 'kadmin.local -q "xst -norandkey -k {} {}" '.format(KDC_USER_KEYTAB_FILEPATH,
                                                                                ' '.join(principal_list))
        kdc_commands.append(create_keytab_cmd)

    kdc_commands.extend([
        'krb5kdc',
        'kadmind',
        'authconfig --enablekrb5 --update',
        'service sshd start',
        'service krb5kdc start',
        'service kadmin start'
    ])

    # Gather keytab file and krb5.conf file in KERBEROS_VOLUME_DIR directory which is mounted on host.
    kdc_commands.append('cp {} {}'.format(KDC_KRB5_CONF_FILEPATH, KERBEROS_VOLUME_DIR))
    if args.kerberos_principals:
        kdc_commands.append('chmod 644 {}'.format(KDC_USER_KEYTAB_FILEPATH))

    kdc_node.execute(command="bash -c '{}'".format('; '.join(kdc_commands)), quiet=quiet_logging)

    logger.info('Validating KDC service health ...')
    _validate_kdc_health(node=kdc_node, services=['sshd', 'krb5kdc', 'kadmin'])

    # Add DSE specific logic on KDC host
    logger.info('Creating `dse` and `HTTP` Kerberos principals for DSE nodes ...')
    for node in nodes:
        key_tab_filename = '{}/{}.keytab'.format(KERBEROS_VOLUME_DIR, node.fqdn)
        kdc_dse_commands = [
            'rm -f {}/{}.keytab'.format(KERBEROS_VOLUME_DIR, node.fqdn),
            'kadmin.local -q "addprinc -randkey dse/{}"'.format(node.fqdn),
            'kadmin.local -q "addprinc -randkey HTTP/{}"'.format(node.fqdn),
            'kadmin.local -q "ktadd -k {} dse/{}"'.format(key_tab_filename, node.fqdn),
            'kadmin.local -q "ktadd -k {} HTTP/{}"'.format(key_tab_filename, node.fqdn),
            'chmod 644 {}'.format(key_tab_filename)
        ]
        kdc_node.execute(command="bash -c '{}'".format('; '.join(kdc_dse_commands)), quiet=quiet_logging)

    # DSE node logic
    logger.info('Updating DSE configurations and starting DSE nodes ...')
    cluster_name = args.dse_cluster_name
    cluster_seeds = ','.join(node.ip_address for node in nodes)
    for node in nodes:
        # kerberos specific commands
        dse_kdc_commands = [
            'cp {}/krb5.conf /etc/.'.format(KERBEROS_VOLUME_DIR),
            'cp {}/{}.keytab {}'.format(KERBEROS_VOLUME_DIR, node.fqdn, DSE_KEYTAB_FILEPATH),
            'chown cassandra:cassandra {}'.format(DSE_KEYTAB_FILEPATH),
            'chmod 600 {}'.format(DSE_KEYTAB_FILEPATH)
        ]
        if args.kerberos_principals:
            dse_kdc_commands.extend([
                'cp {} {}/.'.format(KDC_USER_KEYTAB_FILEPATH, DSE_HOME_DIR),
                'chown cassandra:cassandra {}'.format(DSE_USER_KEYTAB_FILEPATH),
                'chmod 600 {}'.format(DSE_USER_KEYTAB_FILEPATH)
            ])
        node.execute(command="bash -c '{}'".format('; '.join(dse_kdc_commands)), quiet=quiet_logging)
        # DSE config specific commands
        dse_config_commands = [
            'cp {} {}.org'.format(DSE_CASSANDRA_CONF_FILEPATH, DSE_CASSANDRA_CONF_FILEPATH),
            'cp {} {}.org'.format(DSE_CONF_FILEPATH, DSE_CONF_FILEPATH),
            'mkdir -p {}'.format(DSE_CQLSHRC_HOME_DIR)
        ]
        node.execute(command="bash -c '{}'".format('; '.join(dse_config_commands)), quiet=quiet_logging)
        # DSE cassandra.yaml mods
        cassandra_config_data = yaml.load(node.get_file(DSE_CASSANDRA_CONF_FILEPATH))
        cassandra_config_data['cluster_name'] = cluster_name
        cassandra_config_data['listen_address'] = node.ip_address
        cassandra_config_data['rpc_address'] = node.ip_address
        cassandra_config_data['seed_provider'][0]['parameters'][0]['seeds'] = cluster_seeds
        node.put_file(DSE_CASSANDRA_CONF_FILEPATH, yaml.dump(cassandra_config_data))
        # DSE dse.yaml mods
        dse_config_data = yaml.load(node.get_file(DSE_CONF_FILEPATH))
        dse_config_data['audit_logging_options']['enabled'] = True
        dse_config_data['authentication_options'] = {'enabled': True, 'default_scheme': 'internal',
                                                     'allow_digest_with_kerberos': False,
                                                     'plain_text_without_ssl': 'warn', 'transitional_mode': 'disabled',
                                                     'other_schemes': ['internal', 'kerberos'],
                                                     'scheme_permissions': False}
        dse_config_data['role_management_options'] = {'mode': 'internal'}
        dse_config_data['authorization_options'] = {'enabled': True, 'transitional_mode': 'disabled',
                                                    'allow_row_level_security': False}
        dse_config_data['kerberos_options'] = {'keytab': DSE_KEYTAB_FILEPATH,
                                               'service_principal': 'dse/_HOST@{}'.format(realm),
                                               'http_principal': 'HTTP/_HOST@{}'.format(realm),
                                               'qop': 'auth'}
        node.put_file(DSE_CONF_FILEPATH, yaml.dump(dse_config_data))
        # DSE cqlsh specific commands
        cqlsh_cmd_data = node.get_file(DSE_CQLSH_FILEPATH)
        node.put_file(DSE_CQLSH_FILEPATH, re.sub(r'.*(bash code here).*', '. /opt/rh/python27/enable', cqlsh_cmd_data))
        node.execute(command='chmod +x {}'.format(DSE_CQLSH_FILEPATH), quiet=quiet_logging)
        cqlshrc_data = """
            [connection]
            hostname = {}
            port = 9042

            [kerberos]
            service = dse
            qops = auth
        """.format(node.fqdn)
        node.put_file(DSE_CQLSHRC_FILEPATH, textwrap.dedent(cqlshrc_data))
        # start DSE on the node
        node.execute('service dse restart')

    logger.info('Validating DSE service health ...')
    cqlsh_cmd = "cqlsh -u cassandra -p cassandra {} --debug -e 'DESCRIBE KEYSPACES'".format(nodes[0].fqdn)
    _validate_dse_health(nodes=nodes, node_cmd=cqlsh_cmd, node_cmd_expected='system_schema')

    if args.kerberos_principals:
        principal_list = ['{}@{}'.format(primary, realm) for primary in args.kerberos_principals.split(',')]
        logger.info('Creating DSE Kerberos roles {} ...'.format(principal_list))
        logger.info('Kerberos DSE keytab file available on the node at {}'.format(DSE_USER_KEYTAB_FILEPATH))
        for principal in principal_list:
            cqlsh_cmd = """cqlsh -u cassandra -p cassandra {} --debug """.format(nodes[0].fqdn)
            cqlsh_cmd += """-e 'CREATE ROLE "{}" WITH LOGIN = true;""".format(principal)
            cqlsh_cmd += """GRANT EXECUTE on KERBEROS SCHEME to "{}";""".format(principal)
            cqlsh_cmd += """GRANT ALL on ALL KEYSPACES to "{}";'""".format(principal)
            nodes[0].execute(command=cqlsh_cmd, quiet=quiet_logging)

    logger.info('DSE cluster is available and its contacts are: {}'.format(','.join(node.fqdn for node in nodes)))
    logger.info('From its node, DSE can be accessed with: cqlsh -u cassandra -p cassandra')


def _validate_kdc_health(node, services):
    def condition(node, services):
        if all('is running' in (node.execute(command='service {} status'.format(service), quiet=quiet_logging).output)
               for service in services):
            return True
        else:
            logger.debug('Services with poor health: %s',
                         ', '.join(service
                                   for service in services
                                   if 'is running' not in node.execute(command='service {} status'.format(service),
                                                                       quiet=quiet_logging).output))

    def success(time):
        logger.debug('Validated service health in %s seconds.', time)

    def failure(timeout):
        raise TimeoutError('Timed out after {} seconds waiting '
                           'to validate service health.'.format(timeout))
    wait_for_condition(condition=condition, condition_args=[node, services],
                       time_between_checks=3, timeout=600, success=success, failure=failure)


def _validate_dse_health(nodes, node_cmd, node_cmd_expected):
    def condition(nodes, node_cmd, node_cmd_expected):
        if all('running' in (node.execute(command='nodetool statusgossip', quiet=quiet_logging).output)
               for node in nodes) and node_cmd_expected in nodes[0].execute(command=node_cmd,
                                                                            quiet=quiet_logging).output:
            return True
        else:
            logger.debug('Node with poor health: %s',
                         ', '.join(node.fqdn
                                   for node in nodes
                                   if 'running' not in node.execute(command='nodetool statusgossip',
                                                                    quiet=quiet_logging).output))

    def success(time):
        logger.debug('Validated DSE health in %s seconds.', time)

    def failure(timeout):
        raise TimeoutError('Timed out after {} seconds waiting '
                           'to validate DSE health.'.format(timeout))
    wait_for_condition(condition=condition, condition_args=[nodes, node_cmd, node_cmd_expected],
                       time_between_checks=3, timeout=600, success=success, failure=failure)
