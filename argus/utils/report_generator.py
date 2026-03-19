import csv
import json
import os
import sys
import re
from colorama import Fore
import datetime

from argus.config import settings
from argus.utils.util import clean_domain_input


def safe_filename(s, max_length=255):
    s = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', s)
    return s[:max_length]


def ensure_results_directory(domain):
    results_dir = os.path.join(os.getcwd(), settings.RESULTS_DIR, domain)
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    return results_dir


def generate_base_filename(domain, modules_used):
    domain = clean_domain_input(domain)
    sanitized_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # FIX: was NameError when len(modules_used) != 1
    if len(modules_used) == 1:
        module_part = modules_used[0]
    elif len(modules_used) == 0:
        module_part = "scan"
    else:
        module_part = f"multi_{len(modules_used)}mods"

    base_filename = f"{sanitized_domain}_{module_part}_{timestamp}"
    return safe_filename(base_filename)


def generate_txt_report(data, base_filename, results_dir):
    txt_file_path = os.path.join(results_dir, f"{base_filename}.txt")
    try:
        with open(txt_file_path, 'w', encoding='utf-8') as txt_file:
            for module_name, output in data.items():
                txt_file.write(f"=== {module_name} ===\n")
                txt_file.write(f"{output}\n\n")
        print(Fore.GREEN + f"TXT report: {os.path.relpath(txt_file_path)}")
    except Exception as e:
        print(Fore.RED + f"Error generating TXT report: {e}")


def generate_csv_report(data, base_filename, results_dir):
    csv_file_path = os.path.join(results_dir, f"{base_filename}.csv")
    try:
        with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Module", "Output"])
            for module_name, output in data.items():
                clean_output = output.replace('\n', ' | ').replace('\r', '')
                writer.writerow([module_name, clean_output])
        print(Fore.GREEN + f"CSV report: {os.path.relpath(csv_file_path)}")
    except Exception as e:
        print(Fore.RED + f"Error generating CSV report: {e}")


def generate_json_report(data, base_filename, results_dir, domain, modules_used):
    json_file_path = os.path.join(results_dir, f"{base_filename}.json")
    payload = {
        "meta": {
            "target": domain,
            "modules": modules_used,
            "timestamp": datetime.datetime.now().isoformat(),
            "argus_version": "3.0",
        },
        "results": {
            module_name: output.strip().splitlines()
            for module_name, output in data.items()
        },
    }
    try:
        with open(json_file_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(Fore.GREEN + f"JSON report: {os.path.relpath(json_file_path)}")
    except Exception as e:
        print(Fore.RED + f"Error generating JSON report: {e}")


def generate_report(data, domain, modules_used):
    try:
        base_filename = generate_base_filename(domain, modules_used)
        results_dir = ensure_results_directory(clean_domain_input(domain))

        if settings.EXPORT_SETTINGS.get("enable_txt_export", True):
            generate_txt_report(data, base_filename, results_dir)

        if settings.EXPORT_SETTINGS.get("enable_csv_export", False):
            generate_csv_report(data, base_filename, results_dir)

        if settings.EXPORT_SETTINGS.get("enable_json_export", False):
            generate_json_report(data, base_filename, results_dir, domain, modules_used)

    except Exception as e:
        print(Fore.RED + f"Error generating report: {e}")
