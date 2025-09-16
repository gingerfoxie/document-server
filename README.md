# Document Server

Веб-сервер для сохранения и раздачи электронных документов с кэшированием.

## Требования

*   Go 1.24+
*   Docker & Docker Compose
*   PostgreSQL (через Docker)
*   Redis (через Docker)

## Запуск

1.  **Клонируйте репозиторий:**

    ```bash
    git clone <your-repo-url>
    cd document_server
    ```

2.  **Создайте `.env` файл:**

    Скопируйте `.env.example` в `.env` и при необходимости измените значения.
    ```bash
    cp .env.example .env
    ```

3.  **Запустите сервисы с помощью Docker Compose:**

    ```bash
    docker-compose up --build
    ```

    Это запустит PostgreSQL, Redis и само приложение Go.

## Использование

Сервер будет доступен по адресу `http://localhost:8080`.

API Endpoints:

*   `POST /api/register` - Регистрация (требуется `ADMIN_TOKEN` из `.env`)  
*   `POST /api/auth` - Аутентификация  
*   `POST /api/docs` - Загрузка документа  
*   `GET /api/docs` - Получение списка документов  
*   `GET /api/docs/{id}` - Получение документа  
*   `DELETE /api/docs/{id}` - Удаление документа  
*   `DELETE /api/auth/{token}` - Завершение сессии  
