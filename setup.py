#!/usr/bin/env python3
"""
Server Setup Script v3.0 (Python / paramiko)

Полностью автоматическая настройка нового сервера:
  1. Генерация свежего SSH-ключа (ED25519)
  2. Подключение к серверу по паролю root (через paramiko)
  3. Добавление pub-ключа root-у
  4. Создание беспарольного юзера с sudo NOPASSWD
  5. Автозапись в ~/.ssh/config (перед Host *)
  6. Проверка подключения по ключу

Использование:
  python setup.py
  python setup.py --ip 89.124.75.128 --password "rootpass" --user deploy --name production
  python setup.py --ip 89.124.75.128 --password "rootpass" --user deploy --name staging --port 2222

Структура (создаётся автоматически):
  setup.py
  requirements.txt
  keys/
    deploy_89.124.75.128         <- приватный ключ
    deploy_89.124.75.128.pub     <- публичный ключ
    deploy_89.124.75.128_credentials.txt
    deploy_89.124.75.128_ssh_config.txt
  logs/
    2026-02-08_deploy_89.124.75.128.log
"""

import os
import subprocess
import sys
from pathlib import Path

# ── Авто-bootstrap: venv + зависимости ───────────────────────────
SCRIPT_DIR_BOOT = Path(__file__).parent.resolve()
VENV_DIR = SCRIPT_DIR_BOOT / ".venv"

if sys.platform == "win32":
    VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe"
    VENV_PIP = VENV_DIR / "Scripts" / "pip.exe"
else:
    VENV_PYTHON = VENV_DIR / "bin" / "python"
    VENV_PIP = VENV_DIR / "bin" / "pip"


def _inside_venv():
    """Проверяем, запущены ли мы уже внутри .venv."""
    return (
        hasattr(sys, "real_prefix")  # virtualenv
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)  # venv
    )


def _bootstrap():
    """Создаём venv, ставим зависимости и перезапускаем скрипт внутри venv."""
    # Включаем ANSI-коды на Windows
    if sys.platform == "win32":
        os.system("")

    req_file = SCRIPT_DIR_BOOT / "requirements.txt"

    # 1. Создаём venv если нет
    if not VENV_PYTHON.exists():
        print("\n  \033[96m\033[1m>> Создаю виртуальное окружение (.venv)...\033[0m")
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
        print("  \033[92m[OK]\033[0m .venv создан")
    else:
        print("\n  \033[90m[i]\033[0m .venv уже существует")

    # 2. Устанавливаем зависимости
    print("  \033[96m\033[1m>> Устанавливаю зависимости...\033[0m")
    subprocess.check_call(
        [str(VENV_PIP), "install", "-q", "-r", str(req_file)],
        stdout=subprocess.DEVNULL,
    )
    print("  \033[92m[OK]\033[0m Зависимости установлены")

    # 3. Перезапускаем себя внутри venv, пробрасывая все аргументы
    print("  \033[90m[i]\033[0m Перезапускаю скрипт внутри .venv...\n")
    result = subprocess.run(
        [str(VENV_PYTHON), str(Path(__file__).resolve())] + sys.argv[1:]
    )
    sys.exit(result.returncode)


if not _inside_venv():
    _bootstrap()

# ── Если мы здесь, значит работаем внутри venv ───────────────────
import argparse
import getpass
import io
import re
import shutil
from datetime import datetime

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


# ── Пути (портативно, рядом со скриптом) ─────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
KEYS_DIR = SCRIPT_DIR / "keys"
LOGS_DIR = SCRIPT_DIR / "logs"


# ── Цветной вывод (Windows 10+ поддерживает ANSI) ────────────────
class C:
    RESET = "\033[0m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    GRAY = "\033[90m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"


def step(msg):
    print(f"\n{C.CYAN}{C.BOLD}>> {msg}{C.RESET}")

def ok(msg):
    print(f"   {C.GREEN}[OK]{C.RESET} {msg}")

def warn(msg):
    print(f"   {C.YELLOW}[!!]{C.RESET} {msg}")

def err(msg):
    print(f"   {C.RED}[ERR]{C.RESET} {msg}")

def info(msg):
    print(f"   {C.GRAY}[i]{C.RESET} {msg}")


# ── Логирование ──────────────────────────────────────────────────
log_file = None

def log(msg):
    global log_file
    if log_file:
        ts = datetime.now().strftime("%H:%M:%S")
        log_file.write(f"[{ts}] {msg}\n")
        log_file.flush()


# ── Выполнение команды на сервере ────────────────────────────────
def remote_exec(client, command, desc=""):
    """Выполняет команду на сервере, возвращает (stdout, stderr, exit_code)."""
    if desc:
        info(f"$ {desc}")
    stdin, stdout, stderr = client.exec_command(command)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err_out = stderr.read().decode("utf-8", errors="replace").strip()
    log(f"CMD: {command}")
    log(f"  OUT: {out}")
    if err_out:
        log(f"  ERR: {err_out}")
    log(f"  EXIT: {exit_code}")
    return out, err_out, exit_code


# ══════════════════════════════════════════════════════════════════
def main():
    global log_file

    # Включаем ANSI-коды на Windows
    if sys.platform == "win32":
        os.system("")

    # ── Баннер ────────────────────────────────────────────────────
    print(f"""
{C.MAGENTA}{C.BOLD}+===================================================+
|   SERVER SETUP SCRIPT  v3.0  (Python / paramiko)  |
|   SSH Key + User + Sudo -- полный автомат          |
+---------------------------------------------------+
|   Ключи: ./keys/     Логи: ./logs/                |
+==================================================={C.RESET}
""")

    # ── Аргументы командной строки ────────────────────────────────
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--ip", default="")
    parser.add_argument("--root-user", default="root")
    parser.add_argument("--password", default="")
    parser.add_argument("--user", default="")
    parser.add_argument("--name", default="")
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args()

    server_ip = args.ip
    root_user = args.root_user
    root_password = args.password
    new_user = args.user
    server_name = args.name
    ssh_port = args.port

    # ── Интерактивный ввод ────────────────────────────────────────
    if not server_ip:
        server_ip = input("  IP сервера: ").strip()
        if not server_ip:
            err("IP обязателен!")
            sys.exit(1)

    if not root_password:
        root_password = getpass.getpass("  Пароль root: ")
        if not root_password:
            err("Пароль root обязателен!")
            sys.exit(1)

    if not new_user:
        new_user = input("  Имя нового юзера (deploy / admin / dev): ").strip()
        if not new_user:
            err("Имя юзера обязательно!")
            sys.exit(1)

    if not server_name:
        server_name = input("  Название сервера (production / staging / mysite): ").strip()
        if not server_name:
            err("Название сервера обязательно!")
            sys.exit(1)

    # ── Создаём папки ─────────────────────────────────────────────
    KEYS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)

    # ── Имена файлов ──────────────────────────────────────────────
    key_name = f"{new_user}_{server_ip}"
    key_path = KEYS_DIR / key_name
    pub_key_path = KEYS_DIR / f"{key_name}.pub"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Лог ───────────────────────────────────────────────────────
    log_path = LOGS_DIR / f"{datetime.now().strftime('%Y-%m-%d_%H%M')}_{key_name}.log"
    log_file = open(log_path, "w", encoding="utf-8")
    log(f"=== Начало настройки: {new_user} @ {server_ip} ===")

    # ==============================================================
    # ШАГ 1: Генерация SSH-ключа
    # ==============================================================
    step("Шаг 1/6: Генерация SSH-ключа")

    if key_path.exists() or pub_key_path.exists():
        warn(f"Старый ключ {key_name} найден -- пересоздаём")
        log(f"Удаляем старый ключ: {key_path}")
        key_path.unlink(missing_ok=True)
        pub_key_path.unlink(missing_ok=True)

    info(f"Генерируем ED25519 ключ: {key_name}")

    # Генерируем ключ через cryptography и сохраняем в OpenSSH формате
    crypto_key = Ed25519PrivateKey.generate()
    private_pem = crypto_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(private_pem)

    # Публичный ключ в OpenSSH формате
    public_ssh = crypto_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")
    pub_key_str = f"{public_ssh} {new_user}@{server_ip}"
    pub_key_path.write_text(pub_key_str + "\n", encoding="utf-8")

    # Загружаем в paramiko для дальнейшего использования
    private_key = paramiko.Ed25519Key.from_private_key_file(str(key_path))

    ok(f"Ключ создан: {key_path}")
    log(f"Ключ создан: {key_path}")

    # Копируем ключи в ~/.ssh/ для портативности
    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(exist_ok=True)
    ssh_key_path = ssh_dir / key_name
    ssh_pub_path = ssh_dir / f"{key_name}.pub"

    # Удаляем старые ключи (могут быть с ограниченными правами)
    if sys.platform == "win32" and ssh_key_path.exists():
        import subprocess
        subprocess.run(["icacls", str(ssh_key_path), "/grant:r", f"{os.environ.get('USERNAME', 'USER')}:F"],
                       capture_output=True)
    ssh_key_path.unlink(missing_ok=True)
    ssh_pub_path.unlink(missing_ok=True)

    shutil.copy2(key_path, ssh_key_path)
    shutil.copy2(pub_key_path, ssh_pub_path)

    # Права на приватный ключ — SSH требует ограниченные права
    if sys.platform == "win32":
        # Windows: убираем наследование, оставляем доступ только текущему юзеру
        import subprocess
        win_user = os.environ.get("USERNAME", "USER")
        key_str = str(ssh_key_path)
        subprocess.run(["icacls", key_str, "/inheritance:r", "/grant:r", f"{win_user}:R"],
                       capture_output=True)
    else:
        ssh_key_path.chmod(0o600)

    ok(f"Ключ скопирован в ~/.ssh/{key_name}")
    log(f"Ключ скопирован: {ssh_key_path}")

    info(f"Pub: {pub_key_str[:70]}...")

    # Удаляем старый отпечаток сервера из known_hosts (на случай переустановки VPS)
    known_hosts = ssh_dir / "known_hosts"
    if known_hosts.exists():
        import subprocess
        result = subprocess.run(
            ["ssh-keygen", "-R", server_ip],
            capture_output=True, text=True
        )
        if "found" in result.stdout.lower() or "found" in result.stderr.lower():
            info(f"Старый отпечаток {server_ip} удалён из known_hosts")
            log(f"Удалён старый отпечаток из known_hosts для {server_ip}")

    # ==============================================================
    # ШАГ 2: Подключение по паролю root + добавление ключа
    # ==============================================================
    step("Шаг 2/6: Подключаемся к серверу по паролю root")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        info(f"Подключаемся к {root_user}@{server_ip}:{ssh_port}...")
        client.connect(
            hostname=server_ip,
            port=ssh_port,
            username=root_user,
            password=root_password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        ok("Подключение установлено!")
        log("Подключение по паролю: OK")

        # Сохраняем отпечаток сервера в known_hosts для терминала/Cursor
        host_keys_path = ssh_dir / "known_hosts"
        try:
            host_keys = paramiko.HostKeys(str(host_keys_path) if host_keys_path.exists() else None)
            transport = client.get_transport()
            remote_key = transport.get_remote_server_key()
            host_keys.add(server_ip, remote_key.get_name(), remote_key)
            host_keys.save(str(host_keys_path))
            info("Отпечаток сервера сохранён в known_hosts")
            log("Отпечаток сохранён в known_hosts")
        except Exception as e:
            warn(f"Не удалось сохранить отпечаток: {e}")
            log(f"Ошибка сохранения отпечатка: {e}")

    except paramiko.AuthenticationException:
        err("Неверный пароль root!")
        log("ОШИБКА: неверный пароль")
        sys.exit(1)
    except Exception as e:
        err(f"Не удалось подключиться: {e}")
        log(f"ОШИБКА подключения: {e}")
        sys.exit(1)

    # ==============================================================
    # ШАГ 3: Добавляем pub-ключ root-у
    # ==============================================================
    step("Шаг 3/6: Добавляем SSH-ключ root-у")

    add_key_cmd = (
        f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"echo '{pub_key_str}' >> ~/.ssh/authorized_keys && "
        f"sort -u -o ~/.ssh/authorized_keys ~/.ssh/authorized_keys && "
        f"chmod 600 ~/.ssh/authorized_keys && "
        f"echo KEY_ADDED"
    )
    out, _, code = remote_exec(client, add_key_cmd, "Добавляем ключ в authorized_keys")

    if "KEY_ADDED" in out:
        ok("SSH-ключ добавлен для root")
        log("Ключ добавлен для root")
    else:
        err(f"Ошибка при добавлении ключа: {out}")
        log(f"ОШИБКА добавления ключа: {out}")
        sys.exit(1)

    # ==============================================================
    # ШАГ 4: Создаём юзера + sudo + SSH-ключ
    # ==============================================================
    step(f"Шаг 4/6: Создаём юзера '{new_user}' (без пароля, sudo NOPASSWD)")

    create_user_script = f"""set -e

# Создаём юзера если нет
if id '{new_user}' &>/dev/null; then
    echo 'USER_EXISTS'
else
    useradd -m -s /bin/bash '{new_user}'
    echo 'USER_CREATED'
fi

# Блокируем пароль -- вход только по SSH-ключу
passwd -l '{new_user}' 2>/dev/null || usermod -L '{new_user}'

# Sudo без пароля
echo '{new_user} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{new_user}
chmod 440 /etc/sudoers.d/{new_user}

# Добавляем в sudo/wheel группу
if grep -q '^sudo:' /etc/group; then
    usermod -aG sudo '{new_user}'
    echo 'SUDO_GROUP=sudo'
elif grep -q '^wheel:' /etc/group; then
    usermod -aG wheel '{new_user}'
    echo 'SUDO_GROUP=wheel'
fi

# SSH-ключ для юзера
USER_HOME=$(eval echo ~{new_user})
mkdir -p $USER_HOME/.ssh
echo '{pub_key_str}' >> $USER_HOME/.ssh/authorized_keys
sort -u -o $USER_HOME/.ssh/authorized_keys $USER_HOME/.ssh/authorized_keys
chmod 700 $USER_HOME/.ssh
chmod 600 $USER_HOME/.ssh/authorized_keys
chown -R {new_user}:{new_user} $USER_HOME/.ssh

echo 'ALL_DONE'
"""

    out, err_out, code = remote_exec(client, create_user_script, f"useradd + sudo + SSH-ключ")

    if "ALL_DONE" in out:
        ok(f"Юзер '{new_user}' создан и настроен!")
        if "USER_EXISTS" in out:
            info("Юзер уже существовал -- обновлён")
        if "USER_CREATED" in out:
            info("Юзер создан с нуля")
        log(f"Юзер {new_user} создан/обновлён")
    else:
        err(f"Ошибка при создании юзера!")
        print(f"  stdout: {out}")
        print(f"  stderr: {err_out}")
        log(f"ОШИБКА создания юзера: {out} | {err_out}")

    # Закрываем root-соединение
    client.close()

    # ==============================================================
    # ШАГ 5: Автозапись в ~/.ssh/config
    # ==============================================================
    step("Шаг 5/6: Обновляем ~/.ssh/config")

    host_alias = server_name
    key_path_abs = str(key_path.resolve()).replace("\\", "/")
    key_path_config = f"~/.ssh/{key_name}"

    # Блок в стиле существующего конфига
    port_line = f"    Port {ssh_port}\n" if ssh_port != 22 else ""
    host_block = (
        f"# ==== {server_name} ====\n"
        f"Host {host_alias}\n"
        f"    HostName {server_ip}\n"
        f"{port_line}"
        f"    User {new_user}\n"
        f"    IdentityFile {key_path_config}\n"
    )

    # Определяем путь к системному ssh config
    ssh_config_path = Path.home() / ".ssh" / "config"
    ssh_config_path.parent.mkdir(exist_ok=True)

    if ssh_config_path.exists():
        config_text = ssh_config_path.read_text(encoding="utf-8")
    else:
        config_text = ""

    # Проверяем нужно ли добавлять
    if f"Host {host_alias}" in config_text:
        warn(f"Host {host_alias} уже есть в config -- пропускаем")
        insert_text = None
    else:
        insert_text = host_block + "\n"

    if insert_text:

        if config_text:
            # Ищем блок Host * -- вставляем ПЕРЕД ним
            lines = config_text.splitlines(keepends=True)
            insert_index = None

            for i, line in enumerate(lines):
                if re.match(r"^\s*Host\s+\*\s*$", line):
                    insert_index = i
                    # Поднимаемся вверх, захватывая комментарии перед Host *
                    while insert_index > 0 and lines[insert_index - 1].strip().startswith("#"):
                        insert_index -= 1
                    # Пустые строки перед комментарием
                    while insert_index > 0 and lines[insert_index - 1].strip() == "":
                        insert_index -= 1
                    break

            if insert_index is not None:
                # Вставляем перед Host *
                before = "".join(lines[:insert_index])
                after = "".join(lines[insert_index:])
                new_config = before.rstrip("\n") + "\n\n" + insert_text + "\n" + after
                ssh_config_path.write_text(new_config, encoding="utf-8")
                ok(f"Записано в ~/.ssh/config (перед Host *)")
            else:
                # Host * не найден -- дописываем в конец
                with open(ssh_config_path, "a", encoding="utf-8") as f:
                    f.write("\n" + insert_text)
                ok("Записано в ~/.ssh/config (в конец)")
        else:
            # Файла не было -- создаём с нуля
            default_block = (
                "# ==== Основные настройки по умолчанию (ДОЛЖНЫ БЫТЬ В КОНЦЕ!) ====\n"
                "Host *\n"
                "    ForwardAgent no\n"
                "    ForwardX11 no\n"
                "    ServerAliveInterval 60\n"
                "    ServerAliveCountMax 3\n"
                "    User root\n"
                "    IdentitiesOnly yes\n"
            )
            ssh_config_path.write_text(insert_text + "\n" + default_block, encoding="utf-8")
            ok("Создан новый ~/.ssh/config с настройками по умолчанию")

        # Показываем что добавили
        print()
        for line in host_block.splitlines():
            if line.startswith("#"):
                print(f"   {C.WHITE}{line}{C.RESET}")
            elif line.startswith("Host "):
                print(f"   {C.YELLOW}{line}{C.RESET}")
            else:
                print(f"   {C.GRAY}{line}{C.RESET}")
        print()

    log(f"SSH config обновлён: {host_alias}")

    # Сохраняем сниппет-файл (бекап)
    snippet_path = KEYS_DIR / f"{key_name}_ssh_config.txt"
    snippet_content = (
        f"# Автоматически записано в ~/.ssh/config\n"
        f"# Сервер: {server_ip} | Создано: {timestamp}\n"
        f"# Подключение: ssh {host_alias}\n\n"
        f"{host_block}"
    )
    snippet_path.write_text(snippet_content, encoding="utf-8")
    info(f"Бекап сниппета: {snippet_path}")

    # ==============================================================
    # ШАГ 6: Проверка подключения по ключу
    # ==============================================================
    step(f"Шаг 6/6: Проверяем подключение под {new_user} (по ключу)")

    test_client = paramiko.SSHClient()
    test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        test_client.connect(
            hostname=server_ip,
            port=ssh_port,
            username=new_user,
            pkey=private_key,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = test_client.exec_command("whoami")
        whoami = stdout.read().decode().strip()
        test_client.close()

        if whoami == new_user:
            ok(f"Подключение по ключу работает! whoami = {whoami}")
            log("Проверка подключения: OK")
        else:
            warn(f"whoami вернул '{whoami}' вместо '{new_user}'")
            log(f"Проверка: whoami={whoami}")
    except Exception as e:
        warn(f"Не удалось проверить подключение: {e}")
        info(f"Попробуй вручную: ssh {host_alias}")
        log(f"Проверка подключения: ошибка: {e}")

    # ==============================================================
    # Сохраняем credentials
    # ==============================================================
    creds_path = KEYS_DIR / f"{key_name}_credentials.txt"
    creds_content = f"""{'='*50}
  SERVER CREDENTIALS -- {server_ip}
  Создано: {timestamp}
{'='*50}

  IP:             {server_ip}
  Порт:           {ssh_port}
  Юзер:           {new_user}
  Авторизация:    только SSH-ключ (пароль заблокирован)
  Sudo:           NOPASSWD

  SSH-ключ:       ~/.ssh/{key_name}
  Бекап ключа:    ./keys/{key_name}
  Pub-ключ:       ~/.ssh/{key_name}.pub
  SSH-алиас:      {host_alias}

  Быстрое подключение:
    ssh {host_alias}

  Подключение напрямую:
    ssh -i "~/.ssh/{key_name}" {new_user}@{server_ip}

{'='*50}
"""
    creds_path.write_text(creds_content, encoding="utf-8")

    # ==============================================================
    # ИТОГ
    # ==============================================================
    print(f"""
{C.GREEN}{C.BOLD}+===================================================+
|                    ГОТОВО!                         |
+---------------------------------------------------+{C.RESET}
   Сервер:     {C.WHITE}{server_ip}{C.RESET}
   Порт:       {C.WHITE}{ssh_port}{C.RESET}
   Юзер:       {C.WHITE}{new_user}{C.RESET}
   Вход:       {C.GREEN}только SSH-ключ{C.RESET}
   Sudo:       {C.GREEN}NOPASSWD{C.RESET}
   Ключ:       {C.WHITE}~/.ssh/{key_name}{C.RESET}
   Алиас:      {C.YELLOW}{host_alias}{C.RESET}
{C.GREEN}+---------------------------------------------------+{C.RESET}
   Подключение:
     {C.WHITE}ssh {host_alias}{C.RESET}
{C.GREEN}+---------------------------------------------------+{C.RESET}
   {C.GRAY}Credentials: ./keys/{key_name}_credentials.txt{C.RESET}
   {C.GRAY}Лог:         ./logs/{C.RESET}
{C.GREEN}+==================================================={C.RESET}
""")

    log("=== Настройка завершена успешно ===")
    log_file.close()


if __name__ == "__main__":
    main()
