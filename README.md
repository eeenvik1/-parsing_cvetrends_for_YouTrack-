# Description
Скрипт для парсинга сайта cvetrends и работы в YouTrack
```
main.py - основной скрипт, который заводит задачи в Панель мониторинга YouTrack, а также добавляет (изменяет, удаляет) теги для заведенных задач
```

## Usage
Перед началом работы необходимо создать файл `.env` и добавить в него необходимые ссылки и креды.

Создать `.env` файл

```sh
touch parsing_cvetrends_for_YouTrack/app/.env
```

Добавить креды и ссылки в `.env`

```
YOU_TRACK_TOKEN='<YOUR_TOKEN>'
URL1_VAL='<YOUR_URL1>'
URL_VAL='<YOUR_URL>'
USERNAME_VAL='<YOUR_USERNAME>'
PASSWORD_VAL='<YOUR_USERNAME>'
YOU_TRACK_PROJECT_ID = '<YOU_TRACK_PROJECT_ID>'
YOU_TRACK_BASE_URL = '<YOU_TRACK_BASE_URL>'
URL2_VAL = '<YOUR_URL2>'
URL_GET_PRODUCTS = '<URL_GET_PRODUCTS>'
URL_GET_VERSIONS = '<URL_GET_VERSIONS>'
MAIN_URL = "<MAIN_URL>'
EMAIL_HOST = '<EMAIL_HOST>'
EMAIL_PORT = '<EMAIL_PORT>'
EMAIL_HOST_PASSWORD = '<EMAIL_HOST_PASSWORD>'
EMAIL_HOST_USER = '<EMAIL_HOST_USER>'
MSG_TO = '<MSG_TO>'
```

## Install
Для установки запустить
```shell
git clone https://github.com/eeenvik1/parsing_cvetrends_for_YouTrack.git
cd parsing_OpenCVE_for_YouTrack
```

## Usage
```shell
python3 main.py
```


## Example
Пример работы скрипта main.py

