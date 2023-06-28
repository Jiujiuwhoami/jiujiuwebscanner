
import argparse
import concurrent.futures
import os
import importlib
from modules import VulnerabilityScanner as vulscanner
def parse_arguments():
    parser = argparse.ArgumentParser(description='漏洞扫描器')
    parser.add_argument('-t', '--targets', nargs='+', help='目标urls/ips ，Example : http://baidu.com?id=1', required=True)
    parser.add_argument('-f', '--files', nargs='+', help='POCs文件', required=False)
    parser.add_argument('-n', '--threads', type=int, help='最大线程', default=1)
    parser.add_argument('-T', '--target-file', help='多目标urls/ips文件')
    parser.add_argument('-F', '--folder', help='POCs文件夹')
    return parser.parse_args()
def main():
    args = parse_arguments()
    scanner = vulscanner.VulnerabilityScanner([], args.files, args.threads)
    # 如果有ips文件，则重新赋值
    if args.target_file:
        with open(args.target_file, 'r') as file:
            targets = file.read().splitlines()
        scanner.targets = targets
    elif args.targets:
        scanner.targets = args.targets

    if args.folder:
        scanner.load_vulnerabilities_from_folder(args.folder)
    
    scanner.run_detection()
    print("【+】扫描完成")

if __name__ == '__main__':
    main()
