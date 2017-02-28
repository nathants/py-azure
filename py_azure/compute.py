import json
import datetime
import itertools
import logging
import os
import pager
import pool.thread
import random
import shell
import shell.conf
import subprocess
import sys
import time
import util.cached
import util.colors
import util.dicts
import util.exceptions
import util.iter
import util.log
import util.strings
import util.time
from unittest import mock
from shell import run


is_cli = False


ssh_args = ' -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no '


def _now():
    return str(datetime.datetime.utcnow().isoformat()) + 'Z'


def _retry(f):
    """
    retry and idempotent fn a few times
    """
    def fn(*a, **kw):
        for i in itertools.count():
            try:
                return f(*a, **kw)
            except Exception as e:
                if i == 6:
                    raise
                logging.info('retrying: %s.%s, because of: %s', f.__module__, f.__name__, e)
                time.sleep(i + random.random())
    return fn

def login():
    run('az login -u $AZURE_USERNAME -p $AZURE_PASSWORD')
    run('az account set --subscription $AZURE_SUBSCRIPTION')


def logout():
    run('az logout')


def confirm_subscription():
    assert os.environ['AZURE_SUBSCRIPTION'] == json.loads(run('az account show'))['id']


def wait_for_ssh(name=None, group=None, seconds=0, num=0):
    assert num
    assert name or group
    logging.info('wait for ssh...')
    if num and group:
        for _ in range(120):
            try:
                num_ips = len(list(ips(group)))
                logging.info('%s ips available, waiting for %s', num_ips, num)
                if num == num_ips:
                    break
            except:
                pass
            time.sleep(10)
        else:
            assert False, 'failed to wait for the expected number of ips'
    for _ in range(300):
        start = time.time()
        try:
            if name:
                res = shell.run('azc ssh --name', name, '--batch-mode -t 10 -yc "whoami>/dev/null" 2>&1', warn=True)
            else:
                res = shell.run('azc ssh --group', group, '--batch-mode -t 10 -yc "whoami>/dev/null" 2>&1', warn=True)
            ready_ips = [x.split()[-1]
                         for x in res['output'].splitlines()
                         if x.startswith('success: ')]
            num_ready = len(ready_ips)
            logging.info('waiting for %s nodes', num - num_ready)
            if num == num_ready:
                return ready_ips
        except KeyboardInterrupt:
            raise
        time.sleep(max(0, 5 - (time.time() - start)))
    assert False, 'failed to wait for ssh'


def _group_exists(group):
    return run('az group exists --name', group) == 'true'


_data_disk_init = """
(
 echo n
 echo p
 echo 1
 echo
 echo
 echo w
) | sudo fdisk /dev/sdc
sleep 2
yes|sudo mkfs -t ext4 /dev/sdc1
sudo mkdir -p /data
sudo mount /dev/sdc1 /data
sudo chown -R ubuntu:ubuntu /data
uuid=$(sudo blkid|grep sdc1|sed -r 's/.* UUID="([^"]+)".*/\1/')
echo "UUID=$uuid /data ext4 defaults 0 0" | sudo tee -a /etc/fstab
sudo mount -a # verify no errors in fstab
"""

def new(name:  'name of the instance',
        gigs: 'size in gigs of data disk' = 128,
        size: 'instance size' = shell.conf.get_or_prompt_pref('size', __file__, message='instance size'),
        location = shell.conf.get_or_prompt_pref('location',  __file__, message='azure location'),
        no_wait: 'do not wait for ssh'       = False,
        num: 'number of instances' = 1,
        init=_data_disk_init,
        group = None):
    assert not init.startswith('#!'), 'init commands are bash snippets, and should not include a hashbang'
    init = '#!/bin/bash\npath=/tmp/$(uuidgen); echo %s | base64 -d > $path; sudo -u ubuntu bash -e $path /var/log/cloud_init_script.log 2>&1' % util.strings.b64_encode(init)
    if not group:
        group_name = name
    else:
        group_name = group
    assert not list(id(name)), 'name must be globally unique'
    if not _group_exists(group_name):
        run('az group create --name', group_name, '--location', location, echo=True)
        run('az network vnet create --resource-group', group_name, '--name', group_name, '--location', location, '--subnet-name', group_name, echo=True)
        run('az network nsg create --resource-group', group_name, '--name', group_name, '--location', location, echo=True)
        run('az network nsg rule create --resource-group', group_name,
            '--nsg-name', group_name,
            '-n ssh',
            '--priority 100',
            '--source-address-prefix "*"',
            '--destination-address-prefix "*"',
            '--destination-port-range 22',
            '--access Allow',
            '--protocol Tcp',
            echo=True)
    with shell.tempdir():
        with open('cloud-init.txt', 'w') as f:
            f.write(init)
        for i in range(num):
            run('az vm create',
                '--resource-group', group_name,
                '--vnet-name', group_name,
                '--subnet', group_name,
                '--nsg', group_name,
                '--name', (name if num == 1 else '%s-%s' % (name, i + 1)),
                '--image', 'Canonical:UbuntuServer:14.04.4-LTS:latest',
                '--ssh-key-value', '~/.ssh/id_rsa.pub',
                '--admin-username', 'ubuntu',
                '--data-disk-sizes-gb', gigs,
                '--custom-data', 'cloud-init.txt',
                '--size', size,
                ('--no-wait' if num > 1 else ''),
                stream=True)
    wait_for_ssh(group=group, num=num)


def ip(name):
    for vm in json.loads(run('az vm list-ip-addresses --name', name)):
        yield vm['virtualMachine']['network']['publicIpAddresses'][0]['ipAddress']


def ips(group):
    assert _group_exists(group), 'no such group: %s' % group
    for vm in json.loads(run('az vm list-ip-addresses --resource-group', group)):
        yield vm['virtualMachine']['network']['publicIpAddresses'][0]['ipAddress']


def ls():
    for vm in json.loads(run('az vm list --show-details')):
        print(vm['name'],
              vm['location'],
              vm['powerState'].split()[-1],
              vm['hardwareProfile']['vmSize'],
              vm['resourceGroup'].lower(),
              vm['tags'])


def ls_group(group):
    assert _group_exists(group), 'no such group: %s' % group
    for vm in json.loads(run('az vm list --show-details --resource-group', group)):
        print(vm['name'],
              vm['location'],
              vm['powerState'].split()[-1],
              vm['hardwareProfile']['vmSize'],
              vm['resourceGroup'].lower(),
              vm['tags'])


def id(name):
    for vm in json.loads(run('az vm list --show-details')):
        if name == vm['name'] and vm['powerState'].split()[-1] == 'running':
            yield vm['id']


def ids(group):
    assert _group_exists(group), 'no such group: %s' % group
    for vm in json.loads(run('az vm list --show-details')):
        if group.lower() == vm['resourceGroup'].lower() and vm['powerState'].split()[-1] == 'running':
            yield vm['id']


def rm(group=None, name=None):
    if name:
        run('az vm delete --yes --name', name, stream=True)
    else:
        assert _group_exists(group), 'no such group: %s' % group
        run('az group delete --yes --name', group, stream=True)


def ls_groups():
    for group in json.loads(run('az group list')):
        print(group['name'], group['location'], group['properties']['provisioningState'])


def ssh(
        name=None,
        group=None,
        quiet: 'less output' = False,
        cmd: 'cmd to run on remote host, can also be a file which will be read' ='',
        yes: 'no prompt to proceed' = False,
        max_threads: 'max ssh connections' = 20,
        timeout: 'seconds before ssh cmd considered failed' = None,
        no_tty: 'when backgrounding a process, you dont want a tty' = False,
        user: 'specify ssh user' = 'ubuntu',
        key: 'speficy ssh key' = None,
        batch_mode: 'operate like there are many instances, even if only one' = False,
        prefixed: 'when running against a single host, should streaming output be prefixed with name and ip' = False,
        error_message: 'error message to print for a failed host, something like: {id} {name} {ip} {ipv4_private} failed' = ''):
    # tty means that when you ^C to exit, the remote processes are killed. this is usually what you want, ie no lingering `tail -f` instances.
    # no_tty is the opposite, which is good for backgrounding processes, for example: `ec2 ssh $host -nyc 'bash cmd.sh </dev/null &>cmd.log &'
    # TODO backgrounding appears to succeed, but ec2 ssh never exits, when targeting more than 1 host?
    assert name or group
    @_retry
    def f():
        if name:
            x = list(ip(name))
        else:
            x = list(ips(group))
        assert x, 'didnt find any ips'
        return x
    _ips = f()
    if os.path.exists(cmd):
        with open(cmd) as f:
            cmd = f.read()
    if cmd == '-':
        cmd = sys.stdin.read()
    if cmd and 'set -e' not in cmd:
        if cmd.startswith('#!'):
            lines = cmd.splitlines()
            lines.insert(1, 'set -e')
            cmd = '\n'.join(lines)
        else:
            cmd = 'set -e\n' + cmd
    if not (quiet and yes):
        for _ip in _ips:
            logging.info(_ip)
    ssh_cmd = ('ssh -A' + (' -_ip {} '.format(key) if key else '') + (' -tt ' if not no_tty or not cmd else ' -T ') + ssh_args).split()
    if timeout:
        ssh_cmd = ['timeout', '{}s'.format(timeout)] + ssh_cmd
    make_ssh_cmd = lambda _ip: ssh_cmd + [user + '@' + _ip, _remote_cmd(cmd, _ip)]
    if is_cli and not yes and not (len(_ips) == 1 and not cmd):
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    try:
        if len(_ips) > 1 or batch_mode:
            failures = []
            successes = []
            results = []
            def run(_ip):
                def fn():
                    try:
                        shell.run(*make_ssh_cmd(_ip),
                                  callback=_make_callback(_ip, quiet, results),
                                  echo=False,
                                  raw_cmd=True,
                                  stream=False,
                                  hide_stderr=quiet)
                    except:
                        if error_message:
                            print(error_message.format(_ip=_ip), flush=True)
                        msg = util.colors.red('failure: ') + _ip
                        failures.append(msg)
                    else:
                        msg = util.colors.green('success: ') + _ip
                        successes.append(msg)
                    if not quiet:
                        logging.info(msg)
                return fn
            pool.thread.wait(*map(run, _ips), max_threads=max_threads)
            # TODO would be really nice to see these results, plus unknowns:, when ^C to exit early
            if not quiet:
                logging.info('\nresults:')
                for msg in successes + failures:
                    logging.info(' ' + msg)
                logging.info('\ntotals:')
                logging.info(util.colors.green(' successes: ') + str(len(successes)))
                logging.info(util.colors.red(' failures: ') + str(len(failures)))
            if failures:
                sys.exit(1)
            else:
                return results
        elif cmd:
            return shell.run(*make_ssh_cmd(_ips[0]),
                             echo=False,
                             stream=not prefixed,
                             hide_stderr=quiet,
                             raw_cmd=True,
                             callback=_make_callback(_ips[0], quiet) if prefixed else None)
        else:
            subprocess.check_call(ssh_cmd + [user + '@' + _ips[0]])
    except:
        sys.exit(1)


def _remote_cmd(cmd, ip):
    return 'fail_msg="failed to run cmd on instance: %s"; mkdir -p ~/.cmds || echo $fail_msg; path=~/.cmds/$(uuidgen); echo %s | base64 -d > $path || echo $fail_msg; bash $path; code=$?; if [ $code != 0 ]; then echo $fail_msg; exit $code; fi' % (ip, util.strings.b64_encode(cmd)) # noqa


def _make_callback(ip, quiet, append=None):
    name = ip + ': '
    def f(x):
        val = (x if quiet else name + x).replace('\r', '')
        if append:
            append.append(val)
        print(val, flush=True)
    return f


def scp(src, dst, name=None, group=None, yes=False, max_threads=0, user='ubuntu'):
    assert ':' in src + dst, 'you didnt specify a remote path, which starts with ":"'
    if name:
        _ips = list(ip(name))
    else:
        _ips = list(ips(group))
    assert _ips, 'didnt find instances'
    logging.info('targeting:')
    for _ip in _ips:
        logging.info(_ip)
    logging.info('going to scp: %s to %s', src, dst)
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    justify = max(len(_ip) for _ip in _ips)
    def run(_ip, color):
        if color:
            color = getattr(util.colors, color)
        else:
            color = lambda x: x
        name = (_ip + ': ').ljust(justify + 2)
        def fn():
            host = user + '@' + _ip
            _src = host + src if src.startswith(':') else src
            _dst = host + dst if dst.startswith(':') else dst
            try:
                shell.run('scp', ssh_args, _src, _dst, callback=lambda x: print(color(name + x), flush=True))
            except:
                failures.append(util.colors.red('failure: ') + _ip)
            else:
                successes.append(util.colors.green('success: ') + _ip)
        return fn
    failures = []
    successes = []
    pool.thread.wait(*map(run, _ips, itertools.cycle(util.colors._colors) if len(_ips) > 1 else [False]), max_threads=max_threads)
    logging.info('\nresults:')
    for msg in successes + failures:
        logging.info(' ' + msg)
    if failures:
        sys.exit(1)

# TODO when one instance only, dont colorize
# TODO stop using bash -s
def push(src, dst, name=None, group=None, filter=None, yes=False, max_threads=0, user='ubuntu'):
    if name:
        _ips = list(ip(name))
    else:
        _ips = list(ips(group))
    logging.info('targeting:')
    for _ip in _ips:
        logging.info(' %s', _ip)
    logging.info('going to push:\n%s', util.strings.indent(shell.run('bash', _tar_script(src, filter, echo_only=True)), 1))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    script = _tar_script(src, filter)
    failures = []
    successes = []
    justify = max(len(_ip) for _ip in _ips)
    def run(_ip, color):
        if color:
            color = getattr(util.colors, color)
        else:
            color = lambda x: x
        _name = (_ip + ': ').ljust(justify + 2)
        def fn():
            try:
                shell.run('bash', script,
                          '|ssh', ssh_args, user + '@' + _ip,
                          '"mkdir -p', dst, '&& cd', dst, '&& tar xf -"',
                          callback=lambda x: print(color(_name + x), flush=True))
            except:
                failures.append(util.colors.red('failure: ') + _ip)
            else:
                successes.append(util.colors.green('success: ') + _ip)
        return fn
    pool.thread.wait(*map(run, _ips, itertools.cycle(util.colors._colors) if len(_ips) > 1 else [False]), max_threads=max_threads)
    shell.check_call('rm -rf', os.path.dirname(script))
    logging.info('\nresults:')
    for msg in successes + failures:
        logging.info(' ' + msg)
    if failures:
        sys.exit(1)


# TODO stop using bash -s
def pull(src, dst, name, filter=None, yes=False):
    _ip = list(ip(name))[0]
    logging.info('targeting:\n %s', _ip)
    script = _tar_script(src, filter, echo_only=True)
    cmd = ('cat %(script)s |ssh' + ssh_args + 'ubuntu@%(_ip)s bash -s') % locals()
    logging.info('going to pull:')
    logging.info(util.strings.indent(shell.check_output(cmd), 1))
    shell.check_call('rm -rf', os.path.dirname(script))
    if is_cli and not yes:
        logging.info('\nwould you like to proceed? y/n\n')
        assert pager.getch() == 'y', 'abort'
    script = _tar_script(src, filter)
    cmd = ('cd %(dst)s && cat %(script)s | ssh' + ssh_args + 'ubuntu@%(_ip)s bash -s | tar xf -') % locals()
    try:
        shell.check_call(cmd)
    except:
        logging.info('failure for: %s', _ip)
        sys.exit(1)
    finally:
        shell.check_call('rm -rf', os.path.dirname(script))


def _tar_script(src, name, echo_only=False):
    name = ('-name %s' % name) if name else ''
    script = ('cd %(src)s\n'
              'src=$(pwd)\n'
              'cd $(dirname $src)\n'
              "FILES=$(find -L $(basename $src) -type f %(name)s -o -type l %(name)s)\n"
              'echo $FILES|tr " " "\\n"|grep -v \.git 1>&2\n'
              + ('' if echo_only else 'tar cfh - $FILES')) % locals()
    with shell.tempdir(cleanup=False):
        with open('script.sh', 'w') as f:
            f.write(script)
        return os.path.abspath('script.sh')


def emacs(path, name):
    _ip = list(ip(name))[0]
    logging.info(_ip)
    try:
        shell.check_call("nohup emacsclient /ubuntu@{}:{} > /dev/null &".format(_ip, path))
    except:
        sys.exit(1)


def main():
    globals()['is_cli'] = True
    shell.ignore_closed_pipes()
    util.log.setup(format='%(message)s')
    try:
        stream = util.hacks.override('--stream')
        with (shell.set_stream() if stream else mock.MagicMock()):
            shell.dispatch_commands(globals(), __name__)
    except AssertionError as e:
        if e.args:
            logging.info(util.colors.red(e.args[0]))
        sys.exit(1)
