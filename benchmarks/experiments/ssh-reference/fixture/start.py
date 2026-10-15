"""Ephemeral OpenSSH fixture; configuration is supplied only by the controller."""
import json
import os
from pathlib import Path
import subprocess


def main():
    config = json.loads(Path('/fixture.json').read_text())
    subprocess.run(['groupadd', 'proofreaders'], check=True)
    for credential in config['accounts']:
        subprocess.run(['useradd', '-m', '-s', '/bin/sh', '-G', 'proofreaders', credential['user']], check=True)
    subprocess.run(['chpasswd'], input=''.join(
        f"{item['user']}:{item['password']}\n" for item in config['accounts']
    ), text=True, check=True, capture_output=True)
    proof = Path('/srv/lance/proof')
    proof.parent.mkdir(parents=True, mode=0o755)
    proof.write_text(config['object'], encoding='utf-8')
    subprocess.run(['chown', 'root:proofreaders', str(proof)], check=True)
    proof.chmod(0o440)
    Path('/run/sshd').mkdir(parents=True, exist_ok=True)
    subprocess.run(['ssh-keygen', '-A'], check=True, capture_output=True)
    settings = '''Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin no
PermitEmptyPasswords no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
PrintMotd no
UseDNS no
MaxAuthTries 2
MaxSessions 2
LoginGraceTime 10
LogLevel VERBOSE
'''
    settings += 'AllowUsers ' + ' '.join(item['user'] for item in config['accounts']) + '\n'
    Path('/run/sshd_config').write_text(settings)
    os.execv('/usr/sbin/sshd', ['sshd', '-D', '-e', '-f', '/run/sshd_config'])


if __name__ == '__main__':
    main()
