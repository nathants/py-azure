requires python3.4 or higher.

install:

- `sudo apt-get install python3-pip libyaml-dev`

- `git clone https://github.com/nathants/py-azure`

- `cd py-azure`

- `pip3 install -r requirements.txt`

- `pip3 install .`

- `azc -h`


simple usage:

- `azc new test-box --gigs 1023`

- `azc ssh test-box -yc 'ifconfig eth0'`

- `azc ssh test-box`

example of complex usage:

- `bash bootstraps/cassandra_cluster.sh 3.7 test-cluster 25`
