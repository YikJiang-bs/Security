```python
import requests


# HTML转换实体字符

def str_html(source):
    result = ""
    for c in source:
        result += '&#x' + hex(ord(c)) + ';'
    return result.replace('0x', '')


# 从响应中检测Payload是否有效

def check_resp(response, payload, type):
    index = response.find(payload)
    prefix = response[index - 2:index - 1]
    if type == 'Normal' and prefix != '=' and index >= 0:
        return True
    elif type == 'Prop' and prefix == '=' and index >= 0:
        return True

    elif type == 'Escape':
        index = response.find(str_html(payload))
        prefix = response[index - 2:index - 1]
        if prefix == '=' and str_html(payload) in response:
            return True

    elif index >= 0 and prefix == '=':
        return True

    return False


# 实现XSS扫描的主功能
def xss_scan(location):
    url = location.split('?')[0]
    param_list = location.split('?')[1].split('&')
    with open('./dict/xss_payload.txt') as file:
        payload_list = file.readlines()
    for payload in payload_list:
        type = payload.strip().split(':', 1)[0]
        payload = payload.strip().split(':', 1)[1]
        # 针对HTTP信息的检测
        if type == 'Referer' or type == 'User-Agent' or type == 'Cookie':
            header = {type: payload}
            resp = requests.get(url=url, headers=header)
        elif type == 'Escape':
            params = {}
            for param in param_list:
                key = param.split("=")[0]
                params[key] = str_html(payload)
            resp = requests.get(url=url, params=params)
        else:
            params = {}
            for param in param_list:
                key = param.split("=")[0]
                params[key] = payload
            resp = requests.get(url=url, params=params)
        if check_resp(resp.text, payload, type):
            print(f"此处存在XSS漏洞:{payload}")


if __name__ == '__main__':
    # xss_scan('http://192.168.72.148/security/xss/level1.php?name=test')
    # xss_scan('http://192.168.72.148/security/xss/level2.php?keyword=test')
    # xss_scan('http://192.168.72.148/security/xss/level3.php?keyword=test')
    # xss_scan('http://192.168.72.148/security/xss/level4.php?keyword=test')
    # xss_scan('http://192.168.72.148/security/xss/level5.php?keyword=test')
    # xss_scan('http://192.168.72.148/security/xss/level6.php?keyword=test')
    xss_scan('http://192.168.72.148/security/xss/level8.php?keyword=test&a=v')
    # xss_scan('http://192.168.72.148/security/xss/level11.php?keyword=test')
```

