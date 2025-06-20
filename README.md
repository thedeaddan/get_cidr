# Генератор маршрутов для роутеров Keenetic🚧
 ![image](https://github.com/user-attachments/assets/3a9ae1a8-f84e-4cd9-9955-1d6a927f6fec)

 Небольшое Flask-приложение, которое из доменных имён, IP-адресов или CIDR подсетей генерирует команды `route add` и позволяет скачать готовый `.bat` файл. Полезно, когда нужно быстро прописать несколько маршрутов в роутеры Keenetic.
 
Главная идея — получить готовый файл, который затем можно загрузить в таблицу маршрутизации роутеров **Keenetic** и тем самым пополнить их таблицу статических маршрутов.   
![Видео-от-2025-06-17-20-32-07](https://github.com/user-attachments/assets/c074c543-2ef4-4c42-8974-da9357b3eef2)
 ## Особенности
 
 - 📋 Принимает строки с IP, сетями CIDR и доменами
 - 🤖 Автоматически определяет IP доменов и CIDR через `whois`
 - 📝 Формирует набор команд и сохраняет его в `.bat`
 - 📂 Сохраняет историю последних запросов (до 10)
 
 ## Установка
 
 1. Склонируйте репозиторий:
    ```bash
    git clone https://github.com/thedeaddan/get_cidr
    ```
 2. Установите зависимости:
    ```bash
    pip install -r req.txt
    ```
 3. Запустите приложение:
    ```bash
    python3 main.py
    ```
 4. Откройте в браузере [http://localhost:2022](http://localhost:2022).
 
 ## Пример
 
 На вход можно передавать данные построчно, например:
 
 ```
 8.8.8.8
 google.com
 1.1.1.0/24
 ```
 
 После отправки появится таблица с IP, CIDR и готовыми командами, а также кнопка для скачивания `.bat` файла.
 
 
 ## Системные требования
 
 Необходимо наличие установленной утилиты `whois`, Python 3.9+ и интернет для определения CIDR доменов.
 
 ---


