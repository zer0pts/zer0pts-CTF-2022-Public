#!/bin/sh
LENGTH=9
STRENGTH=26
challenge=`dd bs=32 count=1 if=/dev/urandom 2>/dev/null | base64 | tr +/ _. | cut -c -$LENGTH`
echo hashcash -mb$STRENGTH $challenge

echo "hashcash token: "
read token
if [ `expr "$token" : "^[a-zA-Z0-9\+\_\.\:\/]\{52\}$"` -eq 52 ]; then
    hashcash -cdb$STRENGTH -f /tmp/hashcash.sdb -r $challenge $token 2> /dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Correct"
    else
        echo "[-] Wrong"
        exit
    fi
else
    echo "[-] Wrong"
    exit
fi

python3 -c 'import pty; pty.spawn(["/usr/bin/docker", "run", "--rm", "--network=none", "--name", "'$s'", "-it", "readflag_readflag", "timeout", "-s9", "300", "bash"])'
