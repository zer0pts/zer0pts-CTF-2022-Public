FROM python:3.10-slim-buster

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -yqq socat
RUN pip install pycryptodome
ADD challenge/server.py server.py

ENV FLAG "zer0pts{hav3_y0u_unwittin91y_acquir3d_th3_k3y_t0_th3_d00r_t0_th3_N3w_W0r1d?}"
CMD socat TCP-L:9999,fork,reuseaddr EXEC:"python server.py"
