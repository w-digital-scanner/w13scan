FROM python:3.10.5-alpine

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk update && apk --no-cache add git build-base libffi-dev libxml2-dev libxslt-dev libressl-dev gcc
ADD requirements.txt /requirements.txt
RUN pip install -r /requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
ADD . /w13scan/
WORKDIR /w13scan/W13SCAN

ENTRYPOINT ["/bin/ash"]