# pylint: disable=missing-function-docstring
# pylint: disable=missing-module-docstring
# pylint: disable=trailing-whitespace
# pylint: disable=line-too-long

import socket
import paramiko

# ANSI escape codes for text color
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'  # Reset text color to default
PURPLE = '\033[95m'

SERVERS = {
    'host_name': 'ip',
    'localhost': '127.0.0.1'
}

USER = 'avalon'
PASSWORD = 'avalon'
PORT = 22

ANOTHER_USERS = [
    {
        'user': '12345',
        'pass': '12345'
    },
    {
        'user': 'root',
        'pass': 'admin'
    },
]


def is_server_online(host, port):
    try:
        # Попытка установить соединение с сервером
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as open_socket:
            open_socket.settimeout(1)  # Установите таймаут соединения (в секундах)
            open_socket.connect((host, port))
        return True
    except (socket.timeout, ConnectionRefusedError):
        # Сервер не доступен или не существует
        return False
    except socket.gaierror:
        host_ip = SERVERS.get(host)
        return is_server_online(host_ip, port) if host_ip else False


def processing(servers: list):
    for hostname in servers:
        ssh = ssh_connect(hostname, PORT, USER, PASSWORD) if is_server_online(hostname, PORT) else None
        if ssh:
            print(PURPLE + f"OK: {hostname}:" + RESET)
            get_info(ssh)
            continue

        print(RED + f"ERR: {hostname}:- не найден" + RESET)


def ssh_connect(hostname, port, user, password, is_auth_ex=False):
    ssh = create_ssh_client()
    try:
        ssh.connect(hostname, port, user, password)
    except socket.gaierror:
        host_ip = SERVERS.get(hostname)
        if not host_ip:
            return None
        ssh.connect(host_ip, port, user, password)
    except paramiko.ssh_exception.AuthenticationException:
        if is_auth_ex:
            return None

        for user in ANOTHER_USERS:
            ssh = ssh_connect(hostname, port, user['user'], user['pass'], is_auth_ex=True)
            if ssh:
                break
    return ssh


def create_ssh_client():
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return ssh


def get_info(ssh):
    commands = [
        """[ -f /etc/centos-release ] && cat /etc/centos-release || cat /etc/redos-release""",
        'echo "Количество ядер:" &&nproc',
        "echo 'RAM:' && free -g | awk '/^Mem:/{print $2}'",
        'df -h',
        "echo 'Current rpm:' && rpm -qa | grep -E '(RPM_NAME_1|RPM_NAME_2)'" # добавить названия нужных rpm
    ]

    for command in commands:
        exec_command(ssh, command)


def exec_command(ssh, command):
    print(BLUE + f'{command}:' + RESET)
    stdin, stdout, stderr = ssh.exec_command(command)

    info = read(stdout)
    error = read(stderr)
    msg = 'STDOUT: ' + GREEN + info if info else \
          'STDERR: ' + RED + error if error else \
          'STDIN: ' + YELLOW + stdin
    print(msg + RESET)

    return 1


def read(std_info):
    return std_info.read().decode('utf-8')


if __name__ == "__main__":
    processing(SERVERS)
