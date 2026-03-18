import os
import sqlite3
import hashlib
import requests
import tempfile
import shutil
import zipfile
import io
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from yandex_ai_studio_sdk import AIStudio

load_dotenv()

app = Flask(__name__)
DATABASE = 'analysis_results.db'


def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL
            )
        ''')
        conn.commit()


def hash_code(code):
    return hashlib.sha256(code.encode('utf-8')).hexdigest()


def add_result(code_hash, category):
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('INSERT INTO results (code_hash, category) VALUES (?, ?)', (code_hash, category))
            conn.commit()
    except sqlite3.IntegrityError:
        pass


def get_statistics():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT category, COUNT(*) FROM results GROUP BY category')
        return cursor.fetchall()


def get_repo_info(github_url):
    try:
        if 'github.com' not in github_url:
            raise ValueError("Некорректный URL GitHub репозитория")

        api_url = github_url.replace('https://github.com/', 'https://api.github.com/repos/')
        if api_url.endswith('/'):
            api_url = api_url[:-1]

        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        repo_data = response.json()
        return {
            'description': repo_data.get('description', 'Описание отсутствует'),
            'language': repo_data.get('language', 'Не указан'),
            'stars': repo_data.get('stargazers_count', 0),
            'forks': repo_data.get('forks_count', 0)
        }
    except Exception as e:
        return None


def analyze_repo_description(repo_info):
    if not repo_info or not repo_info.get('description'):
        return "Не удалось получить описание репозитория"

    prompt = f"""
    Проанализируй описание GitHub репозитория и кратко охарактеризуй его назначение и функциональность.
    Описание: {repo_info['description']}
    Основной язык: {repo_info['language']}

    Ответ должен быть кратким (1-2 предложения) и содержать только суть проекта.
    """

    try:
        result = model.run([{"role": "user", "text": prompt}])
        return result.alternatives[0].text.strip('```').strip()
    except Exception as e:
        return "Не удалось проанализировать описание репозитория"


def download_repo(github_url):
    if github_url.startswith('github.com'):
        github_url = 'https://' + github_url
    if not github_url.startswith(('https://github.com', 'http://github.com')):
        raise ValueError("Некорректный URL GitHub репозитория")

    github_url = github_url.rstrip('/')
    if github_url.endswith('.git'):
        github_url = github_url[:-4]

    temp_dir = tempfile.mkdtemp()
    repo_name = github_url.split('/')[-1]
    headers = {'User-Agent': 'Mozilla/5.0'}

    try:
        for branch in ('main', 'master'):
            zip_url = f"{github_url}/archive/{branch}.zip"
            response = requests.get(zip_url, headers=headers)
            if response.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                    zip_ref.extractall(temp_dir)
                return os.path.join(temp_dir, f"{repo_name}-{branch}")
        raise ValueError("Не удалось найти ветку main или master")
    except ValueError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise ValueError(f"Ошибка при загрузке репозитория: {str(e)}")


def analyze_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()
    return analyze_code(code)


def analyze_code(code):
    code_hash = hash_code(code)

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT category FROM results WHERE code_hash = ?', (code_hash,))
        existing_result = cursor.fetchone()

    if existing_result:
        return existing_result[0]

    result = model.run([
        {
            "role": "system",
            "text": """Инструкция:

        Вы - эксперт в области кибербезопасности и анализа вредоносного программного обеспечения. Ваша задача - классифицировать предоставленный фрагмент кода по одной из следующих категорий, основываясь на его функциональности и потенциальном вредоносном воздействии:

        1. Потенциально нежелательные приложения (PUA): Приложения, предоставляющие функциональность, которая не раскрывается конечному пользователю. Часто безобидны, но указывают на уязвимости в безопасности.
        2. Фишинг: Пакеты, использующие техники, такие как "путаница с зависимостями", чтобы атаковать организации, выдавая себя за внутренние пакеты. Могут содержать вредоносное ПО.
        3. Эксфильтрация данных: Пакеты, собирающие различные данные с компьютера (переменные среды, токены, файлы паролей и т.д.) и загружающие их на внешний сервер.
        4. Эксфильтрация PII: Эксфильтрация данных, сфокусированная на информации, позволяющей установить личность (токены личного доступа, персональные данные).
        5. Бэкдор: Пакеты, устанавливающие бэкдор на компьютер, предоставляя злоумышленнику удаленный доступ.
        6. Майнер / Похититель криптовалюты: Пакеты, крадущие криптовалюту с зараженного устройства или устанавливающие криптомайнер, использующий ресурсы устройства.
        7. Другие вредоносные пакеты: Остальные вредоносные пакеты, варьирующиеся от деструктивных (повреждение файловой системы) до нацеленных на изменение кода разработчика (маскировка под плагины IDE или CI).

        Формат ответа:

        Ваш ответ должен содержать только название категории, к которой относится предоставленный код. Если код не соответствует ни одной из перечисленных категорий, ответьте "Безопасный код".
        """
        },
        {
            "role": "user",
            "text": code,
        }
    ])

    result_text = result.alternatives[0].text
    result_category = result_text.strip('```').strip()

    valid_categories = [
        "Безопасный код",
        "Потенциально нежелательные приложения (PUA)",
        "Фишинг",
        "Эксфильтрация данных",
        "Эксфильтрация PII",
        "Бэкдор",
        "Майнер / Похититель криптовалюты",
        "Другие вредоносные пакеты"
    ]

    if result_category not in valid_categories:
        raise ValueError(f"Некорректный запрос. Попробуйте ещё раз.")

    add_result(code_hash, result_category)
    return result_category


sdk = AIStudio(
    folder_id=os.environ.get("YANDEX_FOLDER_ID"),
    auth=os.environ.get("YANDEX_AUTH_TOKEN")
)

model = sdk.models.completions("yandexgpt", model_version="rc")
model = model.configure(temperature=0.3)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()

    if 'github_url' in data and data['github_url']:
        try:
            repo_info = get_repo_info(data['github_url'])
            repo_analysis = analyze_repo_description(
                repo_info) if repo_info else "Не удалось получить информацию о репозитории"

            repo_path = download_repo(data['github_url'])
            results = []

            for root, dirs, files in os.walk(repo_path):
                for file in files:
                    if file.endswith(('.py', '.js', '.java', '.c', '.cpp', '.go', '.php', '.rb', '.ts')):
                        file_path = os.path.join(root, file)
                        try:
                            result = analyze_file(file_path)
                            results.append({
                                'file': os.path.relpath(file_path, repo_path),
                                'result': result
                            })
                        except Exception:
                            pass

            shutil.rmtree(repo_path, ignore_errors=True)
            return jsonify({
                "repo_analysis": repo_analysis,
                "repo_info": repo_info,
                "code_analysis": f"Анализ завершен. Проанализировано файлов: {len(results)}",
                "details": results
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 400

    elif 'code' in data and data['code']:
        try:
            result = analyze_code(data['code'])
            return jsonify({"analysis": result})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    return jsonify({"error": "Необходимо предоставить либо код, либо ссылку на GitHub"}), 400


@app.route('/get_chart_data')
def get_chart_data():
    statistics = get_statistics()
    labels = [row[0] for row in statistics]
    values = [row[1] for row in statistics]
    return jsonify({"labels": labels, "values": values})


if __name__ == '__main__':
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")