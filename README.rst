======================================
DSE Cassandra topology for clusterdock
======================================

This repository houses the **DSE Cassandra** topology for `clusterdock`_.

.. _clusterdock: https://github.com/clusterdock/clusterdock

Usage
=====

Assuming you've already installed **clusterdock** (if not, go `read the docs`_),
you use this topology by cloning it to a local folder and then running commands
with the ``clusterdock`` script:

.. _read the docs: http://clusterdock.readthedocs.io/en/latest/

.. code-block:: console

    $ git clone https://github.com/clusterdock/topology_dse.git
    $ clusterdock start topology_dse
    2017-09-20 10:17:38 PM clusterdock.models   INFO     Starting cluster on network (cluster) ...
    2017-09-20 10:17:38 PM clusterdock.models   INFO     Starting node node-1.cluster ...
    2017-09-20 10:17:39 PM clusterdock.models   INFO     Starting node node-2.cluster ...
    2017-09-20 10:17:40 PM clusterdock.topology_dse.start INFO     Updating DSE configurations and starting DSE nodes ...
    Restarting DSE daemon : dse
    DSE daemon starting with only Cassandra enabled (edit /etc/default/dse to enable other features)
    Restarting DSE daemon : dse
    DSE daemon starting with only Cassandra enabled (edit /etc/default/dse to enable other features)
    2017-09-20 10:18:40 PM clusterdock.topology_dse.start INFO     Validating DSE service health ...
    2017-09-20 10:18:53 PM clusterdock.topology_dse.start INFO     DSE cluster is available and its contacts are: node-1.cluster,node-2.cluster
    2017-09-20 10:18:53 PM clusterdock.topology_dse.start INFO     From its node, DSE can be accessed with: cqlsh -u cassandra -p cassandra
    2017-09-20 10:18:53 PM clusterdock.cli      INFO     Cluster started successfully (total time: 1m 14s).

To start a Kerberos based DSE cluster:

.. code-block:: console

    $ clusterdock start --kerberos topology_dse
    2017-09-20 10:21:54 PM clusterdock.models   INFO     Starting cluster on network (cluster) ...
    2017-09-20 10:21:54 PM clusterdock.models   INFO     Starting node kdc.cluster ...
    2017-09-20 10:21:56 PM clusterdock.models   INFO     Starting node node-1.cluster ...
    2017-09-20 10:21:57 PM clusterdock.models   INFO     Starting node node-2.cluster ...
    2017-09-20 10:21:57 PM clusterdock.topology_dse.start INFO     Updating KDC configurations ...
    2017-09-20 10:21:59 PM clusterdock.topology_dse.start INFO     Starting KDC ...
    2017-09-20 10:22:01 PM clusterdock.topology_dse.start INFO     Validating KDC service health ...
    2017-09-20 10:22:01 PM clusterdock.topology_dse.start INFO     Creating `dse` and `HTTP` Kerberos principals for DSE nodes ...
    2017-09-20 10:22:02 PM clusterdock.topology_dse.start INFO     Updating DSE configurations and starting DSE nodes ...
    Restarting DSE daemon : dse
    DSE daemon starting with only Cassandra enabled (edit /etc/default/dse to enable other features)
    Restarting DSE daemon : dse
    DSE daemon starting with only Cassandra enabled (edit /etc/default/dse to enable other features)
    2017-09-20 10:23:02 PM clusterdock.topology_dse.start INFO     Validating DSE service health ...
    2017-09-20 10:23:15 PM clusterdock.topology_dse.start INFO     DSE cluster is available and its contacts are: node-1.cluster,node-2.cluster
    2017-09-20 10:23:15 PM clusterdock.topology_dse.start INFO     From its node, DSE can be accessed with: cqlsh -u cassandra -p cassandra
    2017-09-20 10:23:15 PM clusterdock.cli      INFO     Cluster started successfully (total time: 1m 20s).

To see full usage instructions for the ``start`` action, use ``-h``/``--help``:

.. code-block:: console

    $ clusterdock start topology_dse -h
    usage: clusterdock start [--always-pull] [--namespace ns] [--network nw]
                             [-o sys] [-r url] [-h]
                             [--dse-cluster-name DSE_CLUSTER_NAME] [--kerberos]
                             [--kerberos-config-directory path]
                             [--kerberos-principals princ1,princ2,...]
                             [--kdc-node node [node ...]]
                             [--nodes node [node ...]]
                             topology

    Start a DSE cluster

    positional arguments:
      topology              A clusterdock topology directory

    optional arguments:
      --always-pull         Pull latest images, even if they're available locally
                            (default: False)
      --namespace ns        Namespace to use when looking for images (default:
                            None)
      --network nw          Docker network to use (default: cluster)
      -o sys, --operating-system sys
                            Operating system to use for cluster nodes (default:
                            None)
      -r url, --registry url
                            Docker Registry from which to pull images (default:
                            docker.io)
      -h, --help            show this help message and exit

    DSE arguments:
      --dse-cluster-name DSE_CLUSTER_NAME
                            DSE cluster name to use. (default: Test Cluster)
      --kerberos            If specified, sets up Kerberos based DSE cluster with
                            a KDC node. (default: False)
      --kerberos-config-directory path
                            If specified, mounts this directory to KDC container
                            for Kerberos config files. (default:
                            ~/.clusterdock/kerberos)
      --kerberos-principals princ1,princ2,...
                            If specified, a comma-separated list of Kerberos user
                            principals to create in KDC. (default: None)

    Node groups:
      --kdc-node node [node ...]
                            Nodes of the kdc-node group (default: ['kdc'])
      --nodes node [node ...]
                            Nodes of the nodes group (default: ['node-1',
                            'node-2'])
                            'node-2'])
