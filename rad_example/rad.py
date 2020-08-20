import time
import re
import subprocess
#rad路径
radPath=".././rad.exe"
#w13scan路径
w13scanPath="../W13SCAN/w13scan.py"

def radReptile(target):
    crawlerFile=time.strftime("%m%d%H%M%S", time.localtime())+".txt"
    cmd=[radPath,"-t",target,"-text-output",crawlerFile]
    rad=subprocess.Popen(cmd)
    rad.communicate()
    print("[+]目标"+target+"爬虫结束")
    print(crawlerFile)
    return crawlerFile

def RemoveMethod(crawlerFile):
    removeModefile=crawlerFile+"RemoveMode.txt"
    with open(crawlerFile,"r+") as crawlerFileOpen:
        for target in crawlerFileOpen.readlines():
            #去除GET
            target=re.sub(r"GET\s","",target)
            #去除POST
            target=re.sub(r"POST\s","",target)
            with open(removeModefile,"a") as targetfopen :
                targetfopen.write(target)
    return removeModefile
def Scan(RemoveModeCrawlerFile):
    print("[+]开始扫描")
    cmd=["python",w13scanPath,"--file",RemoveModeCrawlerFile]
    w13scan=subprocess.Popen(cmd,start_new_session=True)
    w13scan.communicate()


if __name__ == '__main__':
    with open("target.txt") as targets:
        for target in targets.readlines():
            print("[+]目标"+target+"开始爬虫")
            Scan(RemoveMethod(radReptile(target)))


