# Используем официальный образ Python
FROM python:3.12-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем зависимости
COPY requirements.txt .

# Устанавливаем их
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь код
COPY . .

# По желанию: создаём не-root пользователя
RUN useradd --create-home botuser
USER botuser

# Запускаем бота
CMD ["python", "bot.py"]