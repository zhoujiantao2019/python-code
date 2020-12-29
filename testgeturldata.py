#update aaron 
import threading
import time
import requests
from bs4 import BeautifulSoup
import re
exitFlag = 0

class myThread (threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
    def run(self):
        print ("开始线程：" + self.name)
        print_time(self.name, 1800, 5)
        print ("退出线程：" + self.name)

def print_time(threadName, delay, counter):
    while counter:
        if exitFlag:
            threadName.exit()
        print ("%s: %s" % (threadName, time.ctime(time.time())))
        try:
          geturldate()
        except:
          print("get data failed,please check networking connect!")
        time.sleep(delay)
        #counter -= 1

def geturldate():
    url = 'http://news.sina.com.cn/china/'
    res = requests.get(url)
    # 使用UTF-8编码
    res.encoding = 'UTF-8'

    # 使用剖析器为html.parseegrep -c '(svm|vmx)' /proc/cpuinfor
    soup = BeautifulSoup(res.text, 'html.parser')

    # 遍历每一个class=news-1的节点
    for news in soup.select('.news-2'):
        # print(news)
        for allli in news.select('li'):
            # print("liall=",allli)
            # print("len=",len(allli))
            li = str(allli)
            # print("li=",li.lstrip())
            n = re.findall(r"href=\"(.+?)\"", li)
            # print ("n=",n[0])
            urlstr = re.findall(r"\"_blank\">(.+?)<", li)
            print(n[0], urlstr[0])

# 创建新线程
thread1 = myThread(1, "Thread-1", 1)
#thread2 = myThread(2, "Thread-2", 2)

# 开启新线程
thread1.start()
#thread2.start()
thread1.join()
#thread2.join()
print ("退出主线程")
