FROM python:3.9-slim

WORKDIR /

RUN apt-get update && apt-get install -y build-essential libgmp-dev libmpc-dev libmpfr-dev
RUN pip install gmpy2

ADD ./solve.py solve.py

CMD python solve.py
