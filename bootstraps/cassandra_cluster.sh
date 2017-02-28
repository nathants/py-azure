#!/bin/bash
set -eu

cd $(dirname $0)

version=$1
cluster_name=$2
num_instances=$3
size=${size:-Standard_DS3_v2}

name="cassandra-${cluster_name}"

azc new $name --group $name --size ${size} --gigs 1023 --num $num_instances

ids=$(azc ids $name)

ips=$(azc ssh --group $name -qyc "ifconfig eth0 |grep 'inet addr'|cut -d: -f2|cut -d' ' -f1")

seeds=$(echo "$ips" | head -n3 | tr '\n' ', '| sed 's:.$::')

azc ssh --group $name -yc "curl -L https://github.com/nathants/bootstraps/tarball/676fdf1 | tar zx && mv nathants-bootstraps* bootstraps"

azc scp --group $name -y ./cassandra.sh :bootstraps/scripts/cassandra.sh

azc ssh --group $name -yc "bash bootstraps/scripts/cassandra.sh $version $cluster_name $seeds"
