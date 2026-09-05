import hashlib, os, pickle, subprocess, random, logging
from Crypto.Cipher import DES, DES3, AES

user_id = input("id: ")
request = get_request()

# ruleid: sqli-py-fstring
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# ok: sqli-py-fstring
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ruleid: sqli-py-concat
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
# ok: sqli-py-concat
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ruleid: sqli-py-percent
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
# ok: sqli-py-percent
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ruleid: sqli-py-indirect-concat
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
# ok: sqli-py-indirect-concat
query2 = "SELECT * FROM users WHERE id = %s"
cursor.execute(query2, (user_id,))

# ruleid: sqli-py-format
query3 = "SELECT * FROM users WHERE id = {}".format(user_id)
cursor.execute(query3)
# ok: sqli-py-format
query4 = "SELECT * FROM users WHERE id = %s"
cursor.execute(query4, (user_id,))

# ruleid: sqli-py-raw-django
User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")
# ok: sqli-py-raw-django
User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])

# ruleid: sqli-py-sqlalchemy-text
text("SELECT * FROM users WHERE id = " + user_id)
# ok: sqli-py-sqlalchemy-text
text("SELECT * FROM users WHERE id = :id")

uid = request.GET.get("id")
# ruleid: sqli-py-taint
cursor.execute(uid)

# ruleid: cmdi-py-os-system-concat
os.system("ping " + host)
# ok: cmdi-py-os-system-concat
subprocess.run(["ping", host])

# ruleid: cmdi-py-subprocess-shell-true
subprocess.run("ping " + host, shell=True)
# ok: cmdi-py-subprocess-shell-true
subprocess.run(["ping", host], shell=False)

# ruleid: cmdi-py-subprocess-string-arg
subprocess.run("ping " + host)
# ok: cmdi-py-subprocess-string-arg
subprocess.run(["ping", host])

# ruleid: cmdi-py-os-popen
os.popen("ping " + host)
# ok: cmdi-py-os-popen
subprocess.run(["ping", host])

# ruleid: cmdi-py-indirect
cmd = "ping " + host
os.system(cmd)
# ok: cmdi-py-indirect
cmd2 = ["ping", host]
subprocess.run(cmd2)

# ruleid: path-traversal-python-open
f = open(request.GET.get("path"))
# ok: path-traversal-python-open
f2 = open("static/config.json")

# ruleid: crypto-md5
h = hashlib.md5(user_id.encode())
# ok: crypto-md5
h2 = hashlib.sha256(user_id.encode())

# ruleid: crypto-sha1
h3 = hashlib.sha1(user_id.encode())
# ok: crypto-sha1
h4 = hashlib.sha256(user_id.encode())

# ruleid: crypto-des
cipher = DES.new(key, DES.MODE_ECB)
# ok: crypto-des
cipher2 = AES.new(key, AES.MODE_GCM)

# ruleid: crypto-ecb-mode
cipher3 = AES.new(key, AES.MODE_ECB)
# ok: crypto-ecb-mode
cipher4 = AES.new(key, AES.MODE_GCM)

# ruleid: crypto-cbc-no-iv
cipher5 = AES.new(key, AES.MODE_CBC, iv)
# ok: crypto-cbc-no-iv
cipher6 = AES.new(key, AES.MODE_GCM, nonce)

# ruleid: crypto-rc4
cipher7 = ARC4.new(key)
# ok: crypto-rc4
cipher8 = AES.new(key, AES.MODE_GCM)

# ruleid: crypto-weak-random-python
tok = random.random() + "token"
# ok: crypto-weak-random-python
jitter = random.random() * 100

# ruleid: nosqli-mongodb-py
db.find({request.GET.get("k"): 1})
# ok: nosqli-mongodb-py
db.find({"status": "active"})

# ruleid: log-forging-python
logging.info(request.GET.get("name"))
# ok: log-forging-python
logging.info("static message")

# ruleid: crypto-rsa-small-key
key = RSA.generate(1024)
# ok: crypto-rsa-small-key
key2 = RSA.generate(4096)

# ruleid: insecure-deserialization-python-pickle
obj = pickle.loads(request.GET.get("data"))
# ok: insecure-deserialization-python-pickle
obj2 = json.loads(request.GET.get("data"))
