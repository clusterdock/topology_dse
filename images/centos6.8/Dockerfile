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
FROM clusterdock/topology_nodebase:centos6.8

ADD dse.repo /etc/yum.repos.d/

ARG JDK_URL=http://download.oracle.com/otn-pub/java/jdk/8u131-b11/d54c1d3a095b4ff2b6607d096fa80163/jdk-8u131-linux-x64.tar.gz
ARG JCE_URL=http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip
ARG JDK_DIRECTORY=/usr/java/jdk1.8.0_131

RUN yum -y update && \
    yum -y install unzip

# Java setup
RUN wget --no-check-certificate \
        --header "Cookie: oraclelicense=accept-securebackup-cookie" -O /tmp/jdk.tar.gz \
        "${JDK_URL}" && \
    mkdir -p /usr/java && \
    tar xf /tmp/jdk.tar.gz -C /usr/java && \
    rm -f /tmp/jdk.tar.gz

RUN wget --no-check-certificate \
        --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" -O /tmp/unlimited_jce_policy.zip \
        "${JCE_URL}" && \
    unzip -jo -d ${JDK_DIRECTORY}/jre/lib/security /tmp/unlimited_jce_policy.zip && \
    rm -f /tmp/unlimited_jce_policy.zip

RUN update-alternatives --install "/usr/bin/java" "java" "${JDK_DIRECTORY}/bin/java" 1
RUN update-alternatives --set java ${JDK_DIRECTORY}/bin/java

# DSE setup
RUN yum -y install dse-full

# Add Python 2.7 as needed by DSE's cqlsh tool
RUN yum install -y scl-utils centos-release-scl-rh
RUN yum install -y python27

# Add Kerberos client specific packages
RUN yum install -y krb5-workstation krb5-devel gcc python26-kerberos
RUN . /opt/rh/python27/enable && pip install pure-sasl kerberos

CMD ["/sbin/init"]
