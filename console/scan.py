"""A dependency-free progress console for the YARA command-line scanner."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def positive(value):
    number = float(value)
    if not 0 < number < float('inf'):
        raise argparse.ArgumentTypeError('Укажите положительное конечное число')
    return number


def collect(target, error):
    if target.is_file():
        return [target]
    files = []
    for root, dirs, names in os.walk(target, onerror=error, followlinks=False):
        dirs[:] = [d for d in dirs if not Path(root, d).is_symlink()
                   and not (hasattr(Path(root, d), 'is_junction')
                            and Path(root, d).is_junction())]
        for name in names:
            path = Path(root, name)
            if not path.is_symlink():
                files.append(path)
        print(f'Подготовка: найдено файлов {len(files)}', flush=True)
    return files


def main():
    parser = argparse.ArgumentParser(description='Проверка YARA с прогрессом')
    parser.add_argument('target', type=Path, help='Файл или папка для проверки')
    parser.add_argument('--rules', required=True, type=Path)
    parser.add_argument('--yara', default='yara64.exe' if os.name == 'nt' else 'yara')
    parser.add_argument('--timeout', type=positive, default=60)
    parser.add_argument('--report', type=Path, default=Path('report.jsonl'))
    args = parser.parse_args()
    executable = shutil.which(args.yara)
    if not executable:
        parser.error('YARA не найдена. Укажите путь через --yara')
    target, rules = args.target.resolve(), args.rules.resolve()
    if not target.exists() or not (target.is_file() or target.is_dir()):
        parser.error('Объект проверки должен быть существующим файлом или папкой')
    if not rules.is_file():
        parser.error('Файл правил не найден')
    started = time.monotonic()
    counts = dict(processed=0, matched_files=0, errors=0, timeouts=0)
    status, total = 'preparing', 0
    # Exclusive creation prevents overwriting a previous report or a scan target.
    try:
        report = args.report.open('x', encoding='utf-8')
    except OSError as exc:
        print(f'Не удалось создать новый отчёт: {exc}', file=sys.stderr)
        return 2
    def record(event):
        report.write(json.dumps(event, ensure_ascii=False) + '\n')
        report.flush()
    def traversal_error(exc):
        counts['errors'] += 1
        record(dict(event='traversal_error', path=exc.filename, error=str(exc)))
    with report:
        record(dict(event='start', target=str(target), rules=str(rules),
                    executable=executable, timeout=args.timeout))
        try:
            excluded = {args.report.resolve(), rules, Path(executable).resolve()}
            files = [p for p in collect(target, traversal_error) if p.resolve() not in excluded]
            total = len(files)
            status = 'running'
            for index, path in enumerate(files, 1):
                print(f'[{index}/{total}] Завершено {counts["processed"]}/{total} '
                      f'({counts["processed"] / total:.0%}) | '
                      f'{time.monotonic() - started:.0f} с | Проверяется: {path}', flush=True)
                try:
                    result = subprocess.run(
                        [executable, '-m', str(rules), str(path)],
                        capture_output=True, timeout=args.timeout,
                        encoding='utf-8', errors='replace',
                    )
                    matched = bool(result.stdout.strip()) and result.returncode == 0
                    counts['matched_files'] += int(matched)
                    counts['errors'] += int(result.returncode != 0 or bool(result.stderr.strip()))
                    record(dict(event='file', path=str(path), returncode=result.returncode,
                                matched=matched, output=result.stdout, errors=result.stderr))
                    if result.returncode != 0 or result.stderr:
                        print('  Ошибка или предупреждение; подробности в отчёте.', flush=True)
                    if matched:
                        print('  Срабатывание YARA; подробности в отчёте.', flush=True)
                except subprocess.TimeoutExpired:
                    counts['timeouts'] += 1
                    record(dict(event='timeout', path=str(path)))
                    print('  Превышен таймаут; файл не проверен полностью.', flush=True)
                except OSError as exc:
                    counts['errors'] += 1
                    record(dict(event='error', path=str(path), error=str(exc)))
                counts['processed'] += 1
            status = 'completed'
        except KeyboardInterrupt:
            status = 'cancelled'
            print('\nПроверка остановлена пользователем.', flush=True)
        except OSError as exc:
            status = 'failed'
            counts['errors'] += 1
            record(dict(event='error', error=str(exc)))
        record(dict(event='summary', status=status, total=total, **counts,
                    elapsed_seconds=round(time.monotonic() - started, 2)))
    print(f'Статус: {status}. Обработано: {counts["processed"]}/{total}; '
          f'срабатываний по файлам: {counts["matched_files"]}; '
          f'ошибок/предупреждений: {counts["errors"]}; таймаутов: {counts["timeouts"]}.')
    print(f'Отчёт: {args.report.resolve()}')
    if status == 'cancelled':
        return 130
    if status != 'completed' or counts['errors'] or counts['timeouts']:
        return 2
    return 1 if counts['matched_files'] else 0


if __name__ == '__main__':
    sys.exit(main())
