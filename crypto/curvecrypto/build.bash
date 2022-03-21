#!/bin/bash
export FLAG="zer0pts{th3_g00d_3ncrypti0n_c0m3s_fr0m_th3_g00d_curv3}"
rm -rf distfiles
mkdir distfiles
python3 ./challenge/task.py > ./distfiles/output.txt
cp ./challenge/task.py ./distfiles/
