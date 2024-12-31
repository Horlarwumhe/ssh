pure-Python  implementation of the SSHv2 protocol. Only client aspect is implemented for now.


For refrences:
SSH specs [https://www.openssh.com/specs.html](https://www.openssh.com/specs.html)

Paramiko [https://github.com/paramiko/paramiko](https://github.com/paramiko/paramiko)

### Installation

```sh
git clone https://github.com/horlarwumhe/ssh.git
cd ssh
pip install .
```

### Run command
```py
from ssh import SSHClient
import curio
import logging
# logging.basicConfig(level=logging.DEBUG)
async def main():
    host = 'localhost'
    port = 22
    async with SSHClient() as s:
        await s.connect(host,port)
        #login with public key
        await s.auth_public_key("username", "/path/to/privatekey")
        # or password
        # await s.auth_password("user","pass")
        cmd = await s.run_command("ls /")
        # read 1024 bytes from stdout
        print((await cmd.stdout()).decode())
        # read 1024 bytes from stderr
        print((await cmd.stderr()).decode())
        # print exit code
        print(cmd.exit_code)
        cmd = await s.run_command("uname -a")
        print((await cmd.stdout()).decode())
        print(cmd.exit_code)
        cmd = await s.run_command("ls /proc")
        while True:
            d = await cmd.stdout()
            if not d:
                break
            print(d.decode())
        print(cmd.exit_code)
        # read 1024 bytes from stderr
        print((await cmd.stderr()).decode())
curio.run(main)
```

### Login with password
```py
async def main():
    host = 'localhost'
    port = 2222
    async with SSHClient() as s:
        await s.connect(host,port)
        await s.auth_password("username","password")
```

### Open port forward

This is similar to 
```sh
ssh -L :8000:ip-api.com:80 user@host
```
```py
from ssh import SSHClient
import curio
from curio.socket import socket

async def copy_data(src, dest):
    # copy data from src to dest
    while True:
        d = await src.recv(1024)
        if not d:
            await src.close()
            await dest.close()
            break
        await dest.send(d)

async def main():
    sock = socket()
    sock.bind(("localhost",8000))
    sock.listen()
    host = 'localhost'
    print("listening on localhost:8000")
    port = 22
    tasks = []
    async with SSHClient() as s:
        await s.connect(host,port)
        #login with public key
        await s.auth_public_key("username", "/path/to/privatekey")
        while True:
            client,a = await sock.accept()
            chan = await s.open_port_forward("ip-api.com",80,a[0],a[1])
            t1 = await curio.spawn(copy_data, chan, client)
            t2 = await curio.spawn(copy_data, client, chan)
            print('port forward opeend')
            tasks.append(t1)
            tasks.append(t2)
curio.run(main)

```

### Usign with sftp

