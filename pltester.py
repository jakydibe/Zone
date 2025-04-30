#!/usr/bin/env python3
import os
import sys
import time
import socket
import subprocess
from pathlib import Path
import traceback

def classify(name: str) -> str:
    """Classify payload by name: reverse, bind, or other"""
    lname = name.lower()
    if 'reverse' in lname:
        return 'reverse'
    if 'bind' in lname:
        return 'bind'
    return 'other'

def test_reverse(tester: str, bin_path: Path, bind_ip: str, bind_port: int, timeout: int = 5) -> bool:
    """Start a listener, run payload, and check if it connects back"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, bind_port))
    sock.listen(1)
    proc = subprocess.Popen([tester, str(bin_path)])
    sock.settimeout(timeout)
    try:
        conn, _ = sock.accept()
        conn.close()
        return True
    except socket.timeout:
        return False
    finally:
        proc.terminate()
        sock.close()

def test_bind(tester: str, bin_path: Path, conn_ip: str, conn_port: int, timeout: int = 5) -> bool:
    """Run payload and attempt to connect to its listening port"""
    proc = subprocess.Popen([tester, str(bin_path)])
    time.sleep(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((conn_ip, conn_port))
        return True
    except Exception:
        return False
    finally:
        proc.terminate()
        sock.close()

def test_other(tester: str, bin_path: Path, timeout: int = 5) -> bool:
    """Run payload and consider it working if exits cleanly"""
    proc = subprocess.Popen([tester, str(bin_path)])
    try:
        proc.wait(timeout=timeout)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.terminate()
        return False

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Test raw-payload bins for basic functionality")
    parser.add_argument('--tester64', default='ploader.exe', help="Path to the x64 payload runner executable")
    parser.add_argument('--tester86', default='ploader86.exe', help="Path to the x86 payload runner executable")
    parser.add_argument('--bins', default='mutations\\mutations', help="Base directory containing x64/ and x86/ subfolders")
    parser.add_argument('--bind-ip', default='0.0.0.0', help="IP to bind listeners on for reverse tests")
    parser.add_argument('--conn-ip', default='127.0.0.1', help="IP to connect to for bind tests")
    parser.add_argument('--port', type=int, default=1234, help="Port used by both bind and reverse payloads")
    parser.add_argument('--batch-size', type=int, default=5, help="Number of tests to buffer before writing to report")
    parser.add_argument('--report-file', default='test_report.txt', help="File to write test results into")
    args = parser.parse_args()

    report_path = Path(args.report_file)
    report_buffer = []
    results = []
    count = 0

    # Read existing report to skip already tested files
    already_tested = set()
    if report_path.exists():
        print(f"[*] Reading existing report to skip tested files: {report_path}")
        with report_path.open('r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(',', 1)
                arch_file_part = parts[0]
                if '/' in arch_file_part:
                    arch, filename = arch_file_part.split('/', 1)
                    already_tested.add( (arch, filename) )
                else:
                    print(f"[!] Invalid entry in report: {line}")

    for arch in ('x64', 'x86'):
        tester = args.tester64 if arch == 'x64' else args.tester86
        dir_path = Path(args.bins) / arch
        if not dir_path.exists():
            print(f"[!] Directory {dir_path} not found, skipping {arch}")
            continue
        for bin_file in sorted(dir_path.glob('*.bin')):
            # Skip if already tested
            if (arch, bin_file.name) in already_tested:
                print(f"[*] Skipping already tested {arch}/{bin_file.name}")
                continue
            
            kind = classify(bin_file.name)
            print(f"[*] Testing {arch}/{bin_file.name} ({kind})...")
            try:
                if kind == 'reverse':
                    ok = test_reverse(tester, bin_file, args.bind_ip, args.port)
                elif kind == 'bind':
                    ok = test_bind(tester, bin_file, args.conn_ip, args.port)
                else:
                    ok = test_other(tester, bin_file)
                status = 'OK' if ok else 'FAIL'
            except Exception as e:
                traceback.print_exc()
                status = 'ERROR'
                error_msg = str(e)
                print(f"    ✗ error during test: {error_msg}")
            else:
                error_msg = ''
                print(f"    -> {status}\n")

            entry = f"{arch}/{bin_file.name},{kind},{status},{error_msg}\n"
            report_buffer.append(entry)
            results.append((arch, bin_file.name, kind, status, error_msg))
            count += 1

            if count % args.batch_size == 0:
                with report_path.open('a') as rf:
                    rf.writelines(report_buffer)
                report_buffer.clear()

    if report_buffer:
        with report_path.open('a') as rf:
            rf.writelines(report_buffer)

    print(f"Tests complete. Results written to {report_path.resolve()}")
    print("Test Summary:")
    for arch, name, kind, status, err in results:
        msg = f" - {arch}/{name}: {kind} => {status}"
        if err:
            msg += f" ({err})"
        print(msg)

if __name__ == '__main__':
    main()