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
import os
import re
import textwrap
import yaml

from clusterdock.models import Cluster, Node
from clusterdock.utils import wait_for_condition

logger = logging.getLogger('clusterdock.{}'.format(__name__))

DEFAULT_NAMESPACE = 'clusterdock'
DEFAULT_OPERATING_SYSTEM = 'centos6.8'

KERBEROS_VOLUME_DIR = '/etc/clusterdock/kerberos'

KDC_ACL_FILEPATH = '/var/kerberos/krb5kdc/kadm5.acl'
KDC_CONF_FILEPATH = '/var/kerberos/krb5kdc/kdc.conf'
KDC_HOSTNAME = 'kdc'
KDC_KEYTAB_FILENAME = 'clusterdock.keytab'
KDC_KRB5_CONF_FILEPATH = '/etc/krb5.conf'
KDC_USER_KEYTAB_FILEPATH = '{}/{}'.format(KERBEROS_VOLUME_DIR, KDC_KEYTAB_FILENAME)

DSE_CQLSHRC_HOME_DIR = '/root/.cassandra'
DSE_HOME_DIR = '/etc/dse'

DSE_CASSANDRA_CONF_FILENAME = 'cassandra.yaml'
DSE_CASSANDRA_CONF_FILEPATH = '{}/cassandra/{}'.format(DSE_HOME_DIR, DSE_CASSANDRA_CONF_FILENAME)
DSE_CONF_FILENAME = 'dse.yaml'
DSE_CONF_FILEPATH = '{}/{}'.format(DSE_HOME_DIR, DSE_CONF_FILENAME)
DSE_CQLSH_FILEPATH = '/usr/bin/cqlsh'
DSE_CQLSHRC_FILEPATH = '{}/cqlshrc'.format(DSE_CQLSHRC_HOME_DIR)
DSE_KEYTAB_FILEPATH = '{}/dse.keytab'.format(DSE_HOME_DIR)
DSE_USER_KEYTAB_FILEPATH = '{}/{}'.format(DSE_HOME_DIR, KDC_KEYTAB_FILENAME)


def main(args):
    dse_image = '{}/{}/clusterdock:dse{}'.format(args.registry,
                                                 args.namespace or DEFAULT_NAMESPACE,
                                                 args.dse_version)
    if args.kerberos:
        _setup_kerberos_nodes(args, dse_image)
    else:
        _setup_non_kerberos_nodes(args, dse_image)


def _setup_non_kerberos_nodes(args, dse_image):
    quiet = not args.verbose

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
            'cp {} {}.orig'.format(DSE_CASSANDRA_CONF_FILEPATH, DSE_CASSANDRA_CONF_FILEPATH),
            'cp {} {}.orig'.format(DSE_CONF_FILEPATH, DSE_CONF_FILEPATH),
            'mkdir -p {}'.format(DSE_CQLSHRC_HOME_DIR)
        ]
        node.execute('; '.join(dse_config_commands), quiet=quiet)
        # DSE cassandra.yaml mods
        _configure_cassandra_yaml(cluster_name, cluster_seeds, node)
        # DSE dse.yaml mods
        dse_config_data = yaml.load(node.get_file(DSE_CONF_FILEPATH))
        dse_config_data['audit_logging_options']['enabled'] = True
        dse_config_data['authentication_options'] = {'enabled': True, 'default_scheme': 'internal'}
        node.put_file(DSE_CONF_FILEPATH, yaml.dump(dse_config_data))
        # DSE cqlsh specific commands
        node.execute(command='chmod +x {}'.format(DSE_CQLSH_FILEPATH), quiet=quiet)
        cqlshrc_data = """
            [connection]
            hostname = {}
            port = 9042
        """.format(node.fqdn)
        _configure_cqlsh(cqlshrc_data, node, quiet)
        # start DSE on the node
        node.execute('service dse restart')

    logger.info('Validating DSE service health ...')
    cqlsh_cmd = ("cqlsh -u cassandra -p cassandra {} "
                 "--debug -e 'DESCRIBE KEYSPACES'").format(nodes[0].fqdn)
    _validate_dse_health(nodes=nodes, node_cmd=cqlsh_cmd, node_cmd_expected='system_schema',
                        quiet=quiet)

    logger.info('DSE cluster is available and its contacts are: {}'.format(
        ','.join(node.fqdn for node in nodes)))
    logger.info('From its node, DSE can be accessed with: cqlsh -u cassandra -p cassandra')


def _setup_kerberos_nodes(args, dse_image):
    quiet = not args.verbose

    kerberos_volume_dir = os.path.expanduser(args.kerberos_config_directory)

    nodes = [Node(hostname=hostname, group='nodes', image=dse_image,
                  volumes=[{kerberos_volume_dir: KERBEROS_VOLUME_DIR}]) for hostname in args.nodes]

    kdc_image = '{}/{}/topology_nodebase_kerberos:{}'.format(args.registry,
                                                             args.namespace or DEFAULT_NAMESPACE,
                                                             args.operating_system
                                                             or DEFAULT_OPERATING_SYSTEM)
    kdc_node = Node(hostname=KDC_HOSTNAME, group='kdc', image=kdc_image,
                    volumes=[{kerberos_volume_dir: KERBEROS_VOLUME_DIR}])
    cluster = Cluster(kdc_node, *nodes)
    cluster.start(args.network)

    logger.info('Updating KDC configurations ...')
    realm = cluster.network.upper()
    krb5_conf_data = kdc_node.get_file(KDC_KRB5_CONF_FILEPATH)
    kdc_node.put_file(KDC_KRB5_CONF_FILEPATH,
                      re.sub(r'EXAMPLE.COM', realm,
                             re.sub(r'example.com', cluster.network,
                                    re.sub(r'kerberos.example.com',
                                           r'{}.{}'.format(KDC_HOSTNAME, cluster.network),
                                           krb5_conf_data))))
    kdc_conf_data = kdc_node.get_file(KDC_CONF_FILEPATH)
    kdc_node.put_file(KDC_CONF_FILEPATH,
                      re.sub(r'EXAMPLE.COM', realm,
                             re.sub(r'\[kdcdefaults\]',
                                    r'[kdcdefaults]\n max_renewablelife = 7d\n max_life = 1d',
                                    kdc_conf_data)))
    acl_data = kdc_node.get_file(KDC_ACL_FILEPATH)
    kdc_node.put_file(KDC_ACL_FILEPATH, re.sub(r'EXAMPLE.COM', realm, acl_data))

    logger.info('Starting KDC ...')
    kdc_commands = [
        'kdb5_util create -s -r {} -P kdcadmin'.format(realm),
        'kadmin.local -q "addprinc -pw {admin_pw} admin/admin@{realm}"'.format(admin_pw='acladmin',
                                                                               realm=realm)
    ]

    # Add the following commands before starting kadmin daemon etc.
    if args.kerberos_principals:
        principal_list = ['{}@{}'.format(principal, realm)
                          for principal in args.kerberos_principals.split(',')]
        create_principals_cmds = ['kadmin.local -q "addprinc -randkey {}"'.format(principal)
                                  for principal in principal_list]
        kdc_commands.extend(create_principals_cmds)

        kdc_commands.append('rm -f {}'.format(KDC_USER_KEYTAB_FILEPATH))
        create_keytab_cmd = 'kadmin.local -q "xst -norandkey -k {} {}" '.format(
            KDC_USER_KEYTAB_FILEPATH, ' '.join(principal_list))
        kdc_commands.append(create_keytab_cmd)

    kdc_commands.extend([
        'krb5kdc',
        'kadmind',
        'authconfig --enablekrb5 --update'
    ])

    kdc_commands.append('cp -f {} {}'.format(KDC_KRB5_CONF_FILEPATH, KERBEROS_VOLUME_DIR))
    if args.kerberos_principals:
        kdc_commands.append('chmod 644 {}'.format(KDC_USER_KEYTAB_FILEPATH))

    kdc_node.execute('; '.join(kdc_commands), quiet=quiet)

    logger.info('Validating Kerberos service health ...')
    _validate_kdc_health(node=kdc_node, services=['krb5kdc', 'kadmin'], quiet=quiet)

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
        kdc_node.execute('; '.join(kdc_dse_commands), quiet=quiet)

    # DSE node logic
    logger.info('Updating DSE configurations and starting DSE nodes ...')
    cluster_name = args.dse_cluster_name
    cluster_seeds = ','.join(node.ip_address for node in nodes)
    for node in nodes:
        # kerberos specific commands
        dse_kdc_commands = [
            'cp {}/krb5.conf /etc'.format(KERBEROS_VOLUME_DIR),
            'cp {}/{}.keytab {}'.format(KERBEROS_VOLUME_DIR, node.fqdn, DSE_KEYTAB_FILEPATH),
            'chown cassandra:cassandra {}'.format(DSE_KEYTAB_FILEPATH),
            'chmod 600 {}'.format(DSE_KEYTAB_FILEPATH)
        ]
        if args.kerberos_principals:
            dse_kdc_commands.extend([
                'cp {} {}'.format(KDC_USER_KEYTAB_FILEPATH, DSE_HOME_DIR),
                'chown cassandra:cassandra {}'.format(DSE_USER_KEYTAB_FILEPATH),
                'chmod 600 {}'.format(DSE_USER_KEYTAB_FILEPATH)
            ])
        node.execute('; '.join(dse_kdc_commands), quiet=quiet)
        # DSE config specific commands
        dse_config_commands = [
            'cp {} {}.orig'.format(DSE_CASSANDRA_CONF_FILEPATH, DSE_CASSANDRA_CONF_FILEPATH),
            'cp {} {}.orig'.format(DSE_CONF_FILEPATH, DSE_CONF_FILEPATH),
            'mkdir -p {}'.format(DSE_CQLSHRC_HOME_DIR)
        ]
        node.execute('; '.join(dse_config_commands), quiet=quiet)
        # DSE cassandra.yaml mods
        _configure_cassandra_yaml(cluster_name, cluster_seeds, node)
        # DSE dse.yaml mods
        dse_config_data = yaml.load(node.get_file(DSE_CONF_FILEPATH))
        dse_config_data['audit_logging_options']['enabled'] = True
        dse_config_data['authentication_options'] = {'enabled': True, 'default_scheme': 'internal',
                                                     'allow_digest_with_kerberos': False,
                                                     'plain_text_without_ssl':
                                                     'warn', 'transitional_mode': 'disabled',
                                                     'other_schemes': ['internal', 'kerberos'],
                                                     'scheme_permissions': False}
        dse_config_data['role_management_options'] = {'mode': 'internal'}
        dse_config_data['authorization_options'] = {'enabled': True, 'transitional_mode':
                                                    'disabled',
                                                    'allow_row_level_security': False}
        dse_config_data['kerberos_options'] = {'keytab': DSE_KEYTAB_FILEPATH,
                                               'service_principal': 'dse/_HOST@{}'.format(realm),
                                               'http_principal': 'HTTP/_HOST@{}'.format(realm),
                                               'qop': 'auth'}
        node.put_file(DSE_CONF_FILEPATH, yaml.dump(dse_config_data))
        # DSE cqlsh specific commands
        node.execute(command='chmod +x {}'.format(DSE_CQLSH_FILEPATH), quiet=quiet)
        cqlshrc_data = """
            [connection]
            hostname = {}
            port = 9042

            [kerberos]
            service = dse
            qops = auth
        """.format(node.fqdn)
        _configure_cqlsh(cqlshrc_data, node, quiet)
        # start DSE on the node
        node.execute('service dse restart')

    logger.info('Validating DSE service health ...')
    cqlsh_cmd = "cqlsh -u cassandra -p cassandra {} --debug -e 'DESCRIBE KEYSPACES'".format(
        nodes[0].fqdn)
    _validate_dse_health(nodes=nodes, node_cmd=cqlsh_cmd, node_cmd_expected='system_schema',
                         quiet=quiet)

    if args.kerberos_principals:
        principal_list = ['{}@{}'.format(principal, realm)
                          for principal in args.kerberos_principals.split(',')]
        logger.info('Creating DSE Kerberos roles {} ...'.format(principal_list))
        logger.info('Kerberos DSE keytab file available on the node at {}'.format(
            DSE_USER_KEYTAB_FILEPATH))
        for principal in principal_list:
            cqlsh_cmd = ("""cqlsh -u cassandra -p cassandra {address} --debug """
                         """-e 'CREATE ROLE "{principal}" WITH LOGIN = true;"""
                         """GRANT EXECUTE on KERBEROS SCHEME to "{principal}";"""
                         """GRANT ALL on ALL KEYSPACES to "{principal}";'""").format(
                             address=nodes[0].fqdn, principal=principal)
            nodes[0].execute(command=cqlsh_cmd, quiet=quiet)

    logger.info('DSE cluster is available and its contacts are: {}'.format(
        ','.join(node.fqdn for node in nodes)))
    logger.info('From its node, DSE can be accessed with: cqlsh -u cassandra -p cassandra')


def _configure_cassandra_yaml(cluster_name, cluster_seeds, node):
    cassandra_config_data = yaml.load(node.get_file(DSE_CASSANDRA_CONF_FILEPATH))
    cassandra_config_data['cluster_name'] = cluster_name
    cassandra_config_data['listen_address'] = node.ip_address
    cassandra_config_data['rpc_address'] = node.ip_address
    cassandra_config_data['seed_provider'][0]['parameters'][0]['seeds'] = cluster_seeds
    node.put_file(DSE_CASSANDRA_CONF_FILEPATH, yaml.dump(cassandra_config_data))


def _configure_cqlsh(cqlshrc_data, node, quiet=True):
    cqlsh_cmd_data = node.get_file(DSE_CQLSH_FILEPATH)
    node.put_file(DSE_CQLSH_FILEPATH, re.sub(r'.*(bash code here).*',
                                             '. /opt/rh/python27/enable', cqlsh_cmd_data))
    node.execute(command='chmod +x {}'.format(DSE_CQLSH_FILEPATH), quiet=quiet)
    node.put_file(DSE_CQLSHRC_FILEPATH, textwrap.dedent(cqlshrc_data))


def _validate_kdc_health(node, services, quiet=True):
    def condition(node, services):
        services_with_poor_health = [service
                                     for service in services
                                     if node.execute(command='service {} status'.format(service),
                                                     quiet=quiet).exit_code != 0]
        if services_with_poor_health:
            logger.debug('Services with poor health: %s', ', '.join(services_with_poor_health))
        # Return True if the list of services with poor health is empty.
        return not bool(services_with_poor_health)

    def success(time):
        logger.debug('Validated service health in %s seconds.', time)

    def failure(timeout):
        raise TimeoutError('Timed out after {} seconds waiting '
                           'to validate service health.'.format(timeout))

    wait_for_condition(condition=condition, condition_args=[node, services],
                       time_between_checks=3, timeout=30, success=success, failure=failure)


def _validate_dse_health(nodes, node_cmd, node_cmd_expected, quiet=True):
    def condition(nodes, node_cmd, node_cmd_expected):
        nodes_with_poor_health = [node for node in nodes
                                  if 'running' not in node.execute(command='nodetool statusgossip',
                                                                   quiet=quiet).output
                                  or node_cmd_expected not in node.execute(command=node_cmd,
                                                                           quiet=quiet).output]
        if nodes_with_poor_health:
            logger.debug('Nodes with poor health: %s',
                         ', '.join(node.fqdn for node in nodes_with_poor_health))
        # Return True if the list of nodes with poor health is empty.
        return not bool(nodes_with_poor_health)

    def success(time):
        logger.debug('Validated DSE health in %s seconds.', time)

    def failure(timeout):
        raise TimeoutError('Timed out after {} seconds waiting '
                           'to validate DSE health.'.format(timeout))

    wait_for_condition(condition=condition, condition_args=[nodes, node_cmd, node_cmd_expected],
                       time_between_checks=3, timeout=90, success=success, failure=failure)
