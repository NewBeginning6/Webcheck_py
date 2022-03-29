import sys
import requests
from termcolor import cprint
import colorama
colorama.init(autoreset=True)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import threading
from random import choice
from time import time
from bs4 import BeautifulSoup
import threadpool

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4482.0 Safari/537.36 Edg/92.0.874.0",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"]
headers = {}
url=[]
g_list = []
queueLock = threading.Lock()


def check_vul(target_url):
    try:
        if target_url.endswith('/'):
            target_url = target_url[:-1]
        target_url = check_url_http(target_url)
        headers["User-Agent"] = choice(USER_AGENTS)
        if "https" in target_url:
            '''requests模块请求一个证书无效的网站的话会直接报错,可以设置verify参数为False解决这个问题,但是设置verify=False会抛出一个InsecureRequestWarning的警告'''
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # 取消SSL验证的警告
            res = requests.get(target_url, verify=False, timeout=6)
        else:
            res = requests.get(target_url, timeout=6)
        res.encoding='utf-8'
        status = res.status_code
        res = res.text
        soup = BeautifulSoup(res,'lxml')
        try:
            span = soup.title.string
        except Exception as e:
            span = ""
        if span:
            print(target_url+"\tstatus:"+str(status)+"\ttitle:"+span)
            return (target_url +"\tstatus:"+str(status)+"\ttitle:" + span)
        else:
            print(target_url+"\tstatus:"+str(status)+"\ttitle:无标题")
            return (target_url+"\tstatus:"+str(status)+"\ttitle:无标题")
    except Exception as e:
        pass


def check_url_http(url):
    isHTTPS = True
    if "http" not in url:
        try:
            target_url = "https://" + url
            """
            requests模块请求一个证书无效的网站的话会直接报错,可以设置verify参数为False解决这个问题,但是设置verify=False会抛出一个InsecureRequestWarning的警告
            """
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # 取消SSL验证的警告
            requests.get(url=target_url, verify=False, timeout=6)
        except Exception as e:
            isHTTPS = False
        finally:
            if isHTTPS:
                target_url = 'https://' + url
                return target_url
            else:
                target_url = 'http://' + url
                return target_url
    else:
        return url


def ip_read():
    file_name = str(sys.argv[2])  # 输入文本名
    for line in open(file_name):
        ip = line.strip()         #消除字符串整体的指定字符,括号里什么都不写,默认消除空格和换行符
        if ip:
            url.append(ip)


# 回调函数的结果保存到g_list数组中,必须两个参数res1为WorkRequest对象,res2为任务函数的结果
def res_printer(res1,res2):
    if res2:
        g_list.append(res2)
    else:
        pass


# 线程池函数
def thread_requestor(urllist):
    pool =  threadpool.ThreadPool(200)                                    # 线程池数量
    reqs =  threadpool.makeRequests(check_vul,urllist,res_printer)        # 使用线程池,res_printer为回调函数
    [pool.putRequest(req) for req in reqs]                                # 简写 for req in reqs pool.putRequest(req)
    pool.wait()


def main():
    cprint(r'''
 __      __      ___.          .__                   __    
/  \    /  \ ____\_ |__   ____ |  |__   ____   ____ |  | __
\   \/\/   // __ \| __ \_/ ___\|  |  \_/ __ \_/ ___\|  |/ /
 \        /\  ___/| \_\ \  \___|   Y  \  ___/\  \___|    < 
  \__/\  /  \___  >___  /\___  >___|  /\___  >\___  >__|_ \
       \/       \/    \/     \/     \/     \/     \/     \/
        ''', "yellow")
    if len(sys.argv) != 3:  # 判断输入长度是否合格
        cprint('''Explain:
        -h      show this help message and exit
        -u      Target URL
        ''', "blue")
        cprint('''Example:
        python3 testpoc.py -u 10.10.10.10
        python3 testpoc.py -r ip.txt''', "magenta")
        return
    a = str(sys.argv[1])  # 输入类型
    if a == '-u':
        target_url = str(sys.argv[2])  # 获取ip地址
        url.append(target_url)
    if a == '-r':
        ip_read()
    """开启多线程"""
    begin = time()
    thread_requestor(url)  # 线程池函数
    for q in g_list:
        with open('存活检测结果.txt', 'a', encoding='utf-8') as f:
            f.writelines(q)
            f.write('\n')
    end = time()
    print('花费时间： %ss' % str(end - begin))


if __name__ == '__main__':
    main()