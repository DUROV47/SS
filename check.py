#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check.py — инвентаризация поверхности веб-сервисов.

Назначение:
    Проверка веб-сервисов на базовое соответствие требованиям безопасности
    в рамках программы ответственного раскрытия (например, Standoff 365).

    Это НЕ сканер уязвимостей и НЕ инструмент эксплуатации. Программа только
    инвентаризирует поверхность: какие сервисы доступны, где есть формы входа,
    какие заголовки безопасности отсутствуют. Используются исключительно
    безопасные методы (GET/HEAD), запросы ограничены по частоте.

Запуск:
    python check.py scope.txt
    python check.py scope.txt --ports 80,443,8080
    python check.py scope.txt --output myreport.txt

Автор: сгенерировано для задачи инвентаризации.
"""

import argparse
import ipaddress
import re
import socket
import ssl
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from urllib3.exceptions import InsecureRequestWarning
except ImportError:
    print("Ошибка: не установлена библиотека 'requests'. "
          "Установите её командой: pip install requests")
    sys.exit(1)

# Отключаем предупреждения о непроверенных сертификатах.
# Мы сознательно не проверяем TLS-сертификаты, т.к. это инвентаризация, а не
# доверенное соединение — self-signed/просроченные сертификаты это нормально
# для исследуемой поверхности и не должны прерывать проверку.
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Константы и настройки по умолчанию
# ---------------------------------------------------------------------------

DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 9000]

# Какие порты по умолчанию считаем HTTPS. Остальные пробуем как HTTP,
# но с фолбэком на HTTPS, если HTTP не отвечает.
HTTPS_PORTS = {443, 8443}

TCP_TIMEOUT = 2        # таймаут TCP-connect (сек)
HTTP_TIMEOUT = 5       # таймаут HTTP-запроса (сек)
MAX_REQUESTS_PER_SEC = 5   # ограничение частоты запросов (rate limit)
MAX_REDIRECTS = 10     # максимум звеньев в цепочке редиректов
DEFAULT_WORKERS = 30   # число параллельных потоков по умолчанию

# Заголовки безопасности, наличие которых мы проверяем.
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]

# User-Agent, явно сообщающий о цели сканирования (инвентаризация, не атака).
USER_AGENT = "SecurityInventoryBot/1.0 (+responsible-disclosure-scan)"


# ---------------------------------------------------------------------------
# Rate limiter — не более N запросов в секунду (потокобезопасный)
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Простой скользящий rate limiter: гарантирует, что за любую секунду
    выполняется не более max_per_sec запросов. Потокобезопасен.
    """

    def __init__(self, max_per_sec):
        self.max_per_sec = max_per_sec
        self._lock = threading.Lock()
        self._times = deque()  # времена последних выполненных запросов

    def acquire(self):
        """Блокируется до тех пор, пока не станет можно сделать запрос."""
        while True:
            with self._lock:
                now = time.monotonic()
                # Убираем из очереди все записи старше 1 секунды.
                while self._times and now - self._times[0] >= 1.0:
                    self._times.popleft()

                if len(self._times) < self.max_per_sec:
                    self._times.append(now)
                    return

                # Нужно подождать, пока освободится «слот».
                sleep_for = 1.0 - (now - self._times[0])

            if sleep_for > 0:
                time.sleep(sleep_for)


# ---------------------------------------------------------------------------
# Структура результата по одной паре IP:порт
# ---------------------------------------------------------------------------

class ServiceResult:
    """Хранит всё, что мы узнали про один сервис (IP:порт)."""

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.tcp_open = False        # открыт ли TCP-порт
        self.error = None            # текст ошибки, если что-то пошло не так
        self.scheme = None           # http / https
        self.final_url = None        # итоговый URL после редиректов
        self.status_code = None      # код HTTP-ответа
        self.server = None           # заголовок Server
        self.location = None         # заголовок Location (последний)
        self.content_type = None     # заголовок Content-Type
        self.body_size = None        # размер тела ответа (байт)
        self.x_powered_by = None     # заголовок X-Powered-By (утечка стека)
        self.has_login_form = False  # обнаружена ли форма входа
        self.login_evidence = []     # чем именно подтверждена форма входа
        self.missing_sec_headers = []  # отсутствующие заголовки безопасности
        self.present_sec_headers = []  # присутствующие заголовки безопасности
        self.redirect_chain = []     # цепочка редиректов (список Location)

    @property
    def target(self):
        return "%s:%d" % (self.ip, self.port)


# ---------------------------------------------------------------------------
# Сетевые проверки
# ---------------------------------------------------------------------------

def is_tcp_open(ip, port, timeout=TCP_TIMEOUT):
    """
    Проверяет доступность порта обычным TCP-connect.
    Возвращает True, если удалось установить соединение.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        # timeout      — порт за фаерволом / хост не отвечает
        # refused      — порт закрыт
        # OSError      — прочие сетевые проблемы (no route и т.п.)
        return False
    finally:
        sock.close()


def build_session():
    """
    Создаёт requests.Session с настроенными повторами на сетевые сбои.
    Редиректы мы обрабатываем вручную, поэтому здесь они отключены на уровне
    запроса (allow_redirects=False передаётся при вызове).
    """
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    # Небольшой retry только на сетевые ошибки соединения, без повторов
    # на «тяжёлых» ответах, чтобы не плодить лишние запросы.
    retry = Retry(
        total=1,
        connect=1,
        read=0,
        backoff_factor=0.5,
        status_forcelist=[],
        allowed_methods=frozenset(["GET", "HEAD"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def follow_redirects(session, url, limiter, result):
    """
    Вручную проходит цепочку редиректов, используя только GET.
    Заполняет result.redirect_chain и возвращает финальный ответ.

    Ручная обработка нужна, чтобы зафиксировать каждый Location в цепочке
    и не превысить rate limit (каждый шаг — отдельный учтённый запрос).
    """
    current_url = url
    response = None

    for _ in range(MAX_REDIRECTS + 1):
        limiter.acquire()  # соблюдаем ограничение частоты на каждый запрос
        response = session.get(
            current_url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,  # редиректы ведём сами
            verify=False,           # не проверяем TLS (self-signed допустимы)
            stream=False,
        )

        # Если это редирект (3xx) и есть Location — идём дальше.
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                break
            result.redirect_chain.append(location)
            # requests корректно склеит относительный Location с базовым URL.
            current_url = requests.compat.urljoin(current_url, location)
            continue

        # Не редирект — финальный ответ.
        break

    result.final_url = current_url
    return response


# Регулярные выражения для детекта формы входа.
# Ищем поле пароля и/или форму, указывающую на логин.
RE_PASSWORD_INPUT = re.compile(
    r"<input[^>]*\btype\s*=\s*['\"]?password['\"]?", re.IGNORECASE
)
RE_LOGIN_FORM_ACTION = re.compile(
    r"<form[^>]*\baction\s*=\s*['\"][^'\"]*login[^'\"]*['\"]", re.IGNORECASE
)
# Дополнительная (мягкая) эвристика — распространённые имена полей/ссылок.
RE_LOGIN_HINT = re.compile(
    r"(name\s*=\s*['\"]?(password|passwd|pwd)['\"]?"
    r"|(sign[\s_-]?in|log[\s_-]?in)\b)",
    re.IGNORECASE,
)


def detect_login_form(html):
    """
    Анализирует HTML и возвращает (bool, list_of_evidence).
    Форма входа считается найденной, если есть поле пароля или форма
    с action, содержащим 'login'.
    """
    evidence = []
    if RE_PASSWORD_INPUT.search(html):
        evidence.append("найден <input type=\"password\">")
    if RE_LOGIN_FORM_ACTION.search(html):
        evidence.append("найден <form action=\"...login...\">")

    found = bool(evidence)

    # Мягкая эвристика добавляется только как пояснение, если уже что-то нашли,
    # либо как самостоятельный, но помеченный как «вероятно» признак.
    if not found and RE_LOGIN_HINT.search(html):
        evidence.append("вероятно (ключевые слова login/signin/password)")
        found = True

    return found, evidence


def analyze_response(response, result):
    """
    Разбирает финальный HTTP-ответ и заполняет поля result:
    статус, заголовки, размер тела, заголовки безопасности, форма входа.
    """
    headers = response.headers

    result.status_code = response.status_code
    result.server = headers.get("Server")
    result.location = headers.get("Location")
    result.content_type = headers.get("Content-Type")
    result.x_powered_by = headers.get("X-Powered-By")

    # Размер тела: берём реальную длину полученного содержимого.
    try:
        result.body_size = len(response.content)
    except Exception:
        # На всякий случай — фолбэк на заголовок Content-Length.
        cl = headers.get("Content-Length")
        result.body_size = int(cl) if cl and cl.isdigit() else None

    # Заголовки безопасности: отделяем присутствующие от отсутствующих.
    for h in SECURITY_HEADERS:
        if h in headers:
            result.present_sec_headers.append(h)
        else:
            result.missing_sec_headers.append(h)

    # Детект формы входа — только по текстовым (HTML) ответам.
    ctype = (result.content_type or "").lower()
    if "html" in ctype or ctype == "":
        try:
            # Ограничиваем анализ разумным объёмом текста.
            text = response.text[:500000]
            result.has_login_form, result.login_evidence = detect_login_form(text)
        except Exception:
            # Не удалось декодировать тело — не критично для инвентаризации.
            pass


def probe_service(ip, port, limiter):
    """
    Полная проверка одного IP:порт.
    Возвращает заполненный ServiceResult.
    """
    result = ServiceResult(ip, port)

    # 1. Проверяем, открыт ли TCP-порт (быстро, с коротким таймаутом).
    result.tcp_open = is_tcp_open(ip, port)
    if not result.tcp_open:
        return result  # порт закрыт — дальше не ходим

    # 2. Выбираем схему. Для «известных» HTTPS-портов начинаем с https,
    #    иначе — с http, с фолбэком на https при неудаче.
    schemes = ["https", "http"] if port in HTTPS_PORTS else ["http", "https"]

    session = build_session()
    last_error = None

    for scheme in schemes:
        url = "%s://%s:%d/" % (scheme, ip, port)
        try:
            response = follow_redirects(session, url, limiter, result)
            if response is not None:
                result.scheme = scheme
                analyze_response(response, result)
                last_error = None
                break
        except requests.exceptions.SSLError as e:
            # SSL-ошибка на https — попробуем следующую схему (http).
            last_error = "SSL error: %s" % _short(e)
            result.redirect_chain = []  # сбрасываем частичную цепочку
            continue
        except requests.exceptions.ConnectTimeout:
            last_error = "connect timeout"
            continue
        except requests.exceptions.ReadTimeout:
            last_error = "read timeout (>%ds)" % HTTP_TIMEOUT
            continue
        except requests.exceptions.ConnectionError as e:
            last_error = "connection error: %s" % _short(e)
            continue
        except requests.exceptions.TooManyRedirects:
            last_error = "слишком много редиректов"
            continue
        except requests.exceptions.RequestException as e:
            last_error = "request error: %s" % _short(e)
            continue
        finally:
            session.close() if scheme == schemes[-1] else None

    if result.status_code is None and last_error:
        result.error = last_error

    return result


def _short(exc, limit=120):
    """Укорачивает текст исключения до читаемой длины."""
    s = str(exc)
    return s if len(s) <= limit else s[:limit] + "..."


# ---------------------------------------------------------------------------
# Чтение входных данных
# ---------------------------------------------------------------------------

def expand_entry(entry):
    """
    Превращает одну строку скоупа в список IP-адресов (строк).

    Поддерживаются:
      * одиночный IP          -> [IP]
      * CIDR-подсеть (a.b.c.d/n) -> все хосты подсети
      * доменное имя          -> резолвится в один/несколько IP

    Для подсетей /31 и /32 возвращаются все адреса как есть; для более
    крупных сетей используются только хосты (без адреса сети и broadcast).
    Возвращает (список_IP, предупреждение_или_None).
    """
    # Строка может содержать ведущий маркер списка "* " из вставленного текста.
    entry = entry.lstrip("*").strip()
    if not entry:
        return [], None

    # 1. CIDR-подсеть?
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError as e:
            return [], "некорректная подсеть '%s': %s" % (entry, e)
        # hosts() исключает сеть/broadcast для сетей крупнее /31.
        hosts = list(net.hosts()) if net.num_addresses > 2 \
            else list(net)
        return [str(h) for h in hosts], None

    # 2. Просто IP-адрес?
    try:
        ipaddress.ip_address(entry)
        return [entry], None
    except ValueError:
        pass

    # 3. Доменное имя — резолвим в IP.
    try:
        infos = socket.getaddrinfo(entry, None, proto=socket.IPPROTO_TCP)
        ips = sorted({info[4][0] for info in infos})
        if ips:
            return ips, None
        return [], "не удалось разрешить имя '%s'" % entry
    except socket.gaierror as e:
        return [], "не удалось разрешить имя '%s': %s" % (entry, e)


def read_scope(path):
    """
    Читает скоуп из файла и разворачивает его в плоский список IP.
    Пропускает пустые строки и комментарии (#). Поддерживает одиночные IP,
    CIDR-подсети и доменные имена. Дубликаты удаляются, порядок сохраняется.
    """
    seen = set()
    targets = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ips, warn = expand_entry(line)
                if warn:
                    print("Предупреждение: %s" % warn)
                for ip in ips:
                    if ip not in seen:
                        seen.add(ip)
                        targets.append(ip)
    except FileNotFoundError:
        print("Ошибка: файл '%s' не найден." % path)
        sys.exit(1)
    except OSError as e:
        print("Ошибка чтения '%s': %s" % (path, e))
        sys.exit(1)
    return targets


def parse_ports(ports_str):
    """Разбирает строку вида '80,443,8080' в список int."""
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)
            else:
                print("Пропущен некорректный порт: %s" % part)
        except ValueError:
            print("Пропущен некорректный порт: %s" % part)
    return ports


# ---------------------------------------------------------------------------
# Формирование отчёта
# ---------------------------------------------------------------------------

def write_report(results, path, scope_file, ports):
    """
    Записывает человекочитаемый отчёт в report.txt.
    Содержит: детальную инвентаризацию, сводку по формам входа и сводку
    по отсутствующим заголовкам безопасности.
    """
    live = [r for r in results if r.status_code is not None]
    login_services = [r for r in live if r.has_login_form]
    insecure_services = [r for r in live if r.missing_sec_headers]

    lines = []
    add = lines.append

    # --- Шапка отчёта ---
    add("=" * 72)
    add("ОТЧЁТ ОБ ИНВЕНТАРИЗАЦИИ ВЕБ-СЕРВИСОВ")
    add("=" * 72)
    add("Дата:            %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    add("Файл скоупа:     %s" % scope_file)
    add("Проверено портов: %s" % ", ".join(str(p) for p in ports))
    add("Всего целей:     %d" % len(results))
    add("Активных HTTP-сервисов: %d" % len(live))
    add("")
    add("Назначение: инвентаризация поверхности (не поиск уязвимостей).")
    add("Методы: только GET/HEAD. Rate limit: %d зап/сек." % MAX_REQUESTS_PER_SEC)
    add("")

    # --- Раздел 1: детально по каждому активному сервису ---
    add("=" * 72)
    add("1. ДЕТАЛЬНАЯ ИНВЕНТАРИЗАЦИЯ")
    add("=" * 72)

    if not live:
        add("Активных веб-сервисов не обнаружено.")
    for r in live:
        add("")
        add("[+] %s  (%s)" % (r.target, r.scheme or "?"))
        add("    URL (итог):     %s" % (r.final_url or "-"))
        add("    Код ответа:     %s" % r.status_code)
        add("    Server:         %s" % (r.server or "—"))
        add("    Content-Type:   %s" % (r.content_type or "—"))
        add("    Location:       %s" % (r.location or "—"))
        add("    Размер тела:    %s байт" %
            (r.body_size if r.body_size is not None else "—"))

        if r.x_powered_by:
            add("    [!] X-Powered-By: %s  (утечка технологии)" % r.x_powered_by)

        if r.redirect_chain:
            add("    Цепочка редиректов:")
            for i, loc in enumerate(r.redirect_chain, 1):
                add("        %d. %s" % (i, loc))

        if r.has_login_form:
            add("    [!] Обнаружена форма входа: %s" %
                "; ".join(r.login_evidence))

        if r.present_sec_headers:
            add("    Заголовки безопасности (есть): %s" %
                ", ".join(r.present_sec_headers))
        if r.missing_sec_headers:
            add("    [!] Отсутствуют заголовки безопасности: %s" %
                ", ".join(r.missing_sec_headers))

    # --- Раздел: цели, где порт открыт, но HTTP не ответил / порт закрыт ---
    tcp_only = [r for r in results if r.tcp_open and r.status_code is None]
    if tcp_only:
        add("")
        add("-" * 72)
        add("Порт открыт (TCP), но HTTP-ответ не получен:")
        for r in tcp_only:
            add("    %s  —  %s" % (r.target, r.error or "нет ответа"))

    # --- Раздел 2: сводка по формам входа ---
    add("")
    add("=" * 72)
    add("2. РЕСУРСЫ С ФОРМАМИ ВХОДА")
    add("=" * 72)
    if login_services:
        for r in login_services:
            add("    %s  ->  %s  (%s)" %
                (r.target, r.final_url or "-", "; ".join(r.login_evidence)))
    else:
        add("    Форм входа не обнаружено.")

    # --- Раздел 3: сводка по отсутствующим заголовкам безопасности ---
    add("")
    add("=" * 72)
    add("3. РЕСУРСЫ С ОТСУТСТВУЮЩИМИ ЗАГОЛОВКАМИ БЕЗОПАСНОСТИ")
    add("=" * 72)
    if insecure_services:
        for r in insecure_services:
            add("    %s  ->  отсутствуют: %s" %
                (r.target, ", ".join(r.missing_sec_headers)))
    else:
        add("    У всех активных сервисов присутствуют проверяемые заголовки.")

    add("")
    add("=" * 72)
    add("Конец отчёта.")
    add("=" * 72)

    # Запись в файл.
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        print("Ошибка записи отчёта в '%s': %s" % (path, e))
        sys.exit(1)


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Инвентаризация поверхности веб-сервисов "
                    "(responsible disclosure).",
        epilog="Пример: python check.py scope.txt --ports 80,443,8080",
    )
    parser.add_argument("scope", help="файл со списком IP-адресов (по строке)")
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="список портов через запятую (по умолчанию: %s)" %
             ",".join(str(p) for p in DEFAULT_PORTS),
    )
    parser.add_argument(
        "--output", default="report.txt",
        help="файл для отчёта (по умолчанию: report.txt)",
    )
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS,
        help="число параллельных потоков (по умолчанию: %d)" % DEFAULT_WORKERS,
    )
    args = parser.parse_args()

    targets = read_scope(args.scope)
    ports = parse_ports(args.ports)

    if not targets:
        print("Скоуп пуст — нечего проверять.")
        sys.exit(0)
    if not ports:
        print("Список портов пуст.")
        sys.exit(1)

    workers = max(1, args.workers)
    total = len(targets) * len(ports)
    print("Цели: %d IP x %d портов = %d проверок." %
          (len(targets), len(ports), total))
    print("Потоков: %d. Rate limit: %d HTTP-запросов/сек. "
          "Таймауты: TCP %ds, HTTP %ds.\n" %
          (workers, MAX_REQUESTS_PER_SEC, TCP_TIMEOUT, HTTP_TIMEOUT))

    # Общий rate limiter на все потоки: ограничивает именно HTTP-запросы
    # (не TCP-проверки), поэтому параллелизм ускоряет перебор закрытых портов,
    # не нарушая лимит 5 запросов/сек к веб-приложениям.
    limiter = RateLimiter(MAX_REQUESTS_PER_SEC)
    results = []
    results_lock = threading.Lock()
    done = 0
    done_lock = threading.Lock()

    # Полный список заданий (IP, порт).
    jobs = [(ip, port) for ip in targets for port in ports]

    def worker(job):
        ip, port = job
        try:
            return probe_service(ip, port, limiter)
        except Exception as e:
            # Любая непредвиденная ошибка не должна ронять весь скан.
            res = ServiceResult(ip, port)
            res.error = "внутренняя ошибка: %s" % _short(e)
            return res

    def format_status(res):
        if res.status_code is not None:
            flags = []
            if res.has_login_form:
                flags.append("login")
            if res.missing_sec_headers:
                flags.append("%d missing hdr" % len(res.missing_sec_headers))
            return "HTTP %s%s" % (
                res.status_code,
                (" [" + ", ".join(flags) + "]") if flags else "",
            )
        if res.tcp_open:
            return "tcp open, no http"
        return "closed"

    executor = ThreadPoolExecutor(max_workers=workers)
    futures = [executor.submit(worker, job) for job in jobs]

    try:
        for fut in as_completed(futures):
            res = fut.result()
            with results_lock:
                results.append(res)
            with done_lock:
                done += 1
                n = done
            print("[%d/%d] %-21s  %s" % (n, total, res.target, format_status(res)))
    except KeyboardInterrupt:
        # Прерывание: гасим пул и пишем частичный отчёт по тому, что успели.
        print("\nПрервано пользователем. Останавливаю потоки и пишу отчёт...")
        executor.shutdown(wait=False, cancel_futures=True)
        write_report(results, args.output, args.scope, ports)
        sys.exit(130)

    executor.shutdown(wait=True)
    write_report(results, args.output, args.scope, ports)
    print("\nГотово. Отчёт сохранён в: %s" % args.output)


if __name__ == "__main__":
    main()
