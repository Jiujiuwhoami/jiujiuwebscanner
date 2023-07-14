
import wx
import argparse
import concurrent.futures
import os
import importlib
from modules import VulnerabilityScanner as vulscanner
from modules import VulnerabilityScannerGUI as vulscannergui
def parse_arguments():
    parser = argparse.ArgumentParser(description='漏洞扫描器')
    parser.add_argument('-t', '--targets', nargs='+', help='目标urls/ips ，Example : http://baidu.com?id=1', required=False)
    parser.add_argument('-f', '--files', nargs='+', help='POCs文件', required=False)
    parser.add_argument('-n', '--threads', type=int, help='最大线程', default=1)
    parser.add_argument('-T', '--target_file', help='多目标urls/ips文件')
    parser.add_argument('-F', '--poc_folder', help='POCs文件夹')
    parser.add_argument('--gui', action='store_true', help='启动GUI界面')
    #parser.set_defaults(gui=True)  
    return parser.parse_args()
def main():
    args = parse_arguments()
    scanner = vulscanner.VulnerabilityScanner(targets=args.targets, target_files=args.target_file,files=args.files, files_pocs=args.poc_folder,threads=args.threads)
    if args.gui:
        app = wx.App()
        frame = vulscannergui.VulnerabilityScannerGUI(None, title="jiujiuwebscanner")
        frame.Show()
        app.MainLoop()
    else:
        scanner.run_detection()
        

if __name__ == '__main__':
    main()
    print("【+】扫描完成")
