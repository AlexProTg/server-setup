# Server Setup Script v3.0

Полностью автоматическая настройка нового Linux-сервера за один запуск:

1. Генерация свежего SSH-ключа (ED25519)
2. Подключение к серверу по паролю root (через paramiko)
3. Добавление pub-ключа root-у
4. Создание беспарольного юзера с sudo NOPASSWD
5. Автозапись в `~/.ssh/config` (перед `Host *`)
6. Проверка подключения по ключу

## Установка и запуск (одна команда)

```bash
git clone https://github.com/AlexProTg/server-setup.git && cd server-setup && python setup.py
```

Скрипт сам создаст `.venv`, установит все зависимости и запустится.

### Интерактивный режим

```bash
python setup.py
```

Скрипт спросит IP, пароль root, имя юзера и название сервера.

### С аргументами

```bash
python setup.py --ip 89.124.75.128 --password "rootpass" --user deploy --name production
python setup.py --ip 89.124.75.128 --password "rootpass" --user deploy --name staging --port 2222
```

### Параметры

| Параметр | Описание | По умолчанию |
|---|---|---|
| `--ip` | IP-адрес сервера | интерактивно |
| `--password` | Пароль root | интерактивно |
| `--user` | Имя нового юзера | интерактивно |
| `--name` | Название/алиас сервера | интерактивно |
| `--root-user` | Пользователь для первого подключения | `root` |
| `--port` | SSH-порт | `22` |

## Что создаётся

```
server-setup/
├── setup.py
├── requirements.txt
├── keys/                              # .gitignore'd
│   ├── deploy_89.124.75.128           # приватный ключ
│   ├── deploy_89.124.75.128.pub       # публичный ключ
│   ├── deploy_89.124.75.128_credentials.txt
│   └── deploy_89.124.75.128_ssh_config.txt
└── logs/                              # .gitignore'd
    └── 2026-02-08_1200_deploy_89.124.75.128.log
```

Ключи также копируются в `~/.ssh/` с правильными правами.

## После запуска

Подключение к серверу в одну команду:

```bash
ssh production
```

## Требования

- Python 3.8+
- paramiko >= 3.4
- cryptography >= 42.0
- Доступ к серверу по паролю root (первый раз)

## Безопасность

- Пароль юзера блокируется — вход **только по SSH-ключу**
- Приватные ключи **никогда не коммитятся** (`.gitignore`)
- Права на ключ: `600` (Linux) / только текущий юзер (Windows)
- `sudo NOPASSWD` для удобства DevOps-операций

## Лицензия

MIT
