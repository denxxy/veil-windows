@echo off
rem Запуск Veil на Windows. Требуется Python 3.8+ с python.org (галочка
rem "Add python.exe to PATH" при установке).
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python не найден. Установите его с https://www.python.org/downloads/
    echo и во время установки отметьте "Add python.exe to PATH".
    pause
    exit /b 1
)

echo Проверяю зависимости…
python -m pip install -q -r requirements.txt
if errorlevel 1 (
    echo Не удалось установить зависимости. Проверьте интернет.
    pause
    exit /b 1
)

python veil_client.py
if errorlevel 1 (
    echo.
    echo Клиент завершился с ошибкой.
    pause
)
