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
        #read from stdout
        print((await cmd.stdout()).decode())
        # read from stderr
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
        # read from stderr
        print((await cmd.stderr()).decode())

        # wait for process completion (similar to `subprocess.Popen.wait()`)
        cmd = await s.run_command("sleep 5")
        exit_code = await cmd.wait()
        print(exit_code)


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

##### stdout/stderr

The `stdout` and `stderr` functions block until at least one byte of data is available or the process exits. Use `block=True` to wait until all data is read (process completion)."

```py
await cmd.stdout(block=True)
# Waits until the process exits and returns all the data at once
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

### Using sftp client

```py
import os
from ssh import SSHClient
import curio
import logging
import time
import pathlib
# logging.basicConfig(level=logging.INFO)
async def main():
    host = 'localhost'
    port = 22
    async with SSHClient() as s:
        await s.connect(host,port)
        #login with public key
        await s.auth_public_key("ubuntu", "/path/to/key")
        # or password
        # await s.auth_password("user","pass")
        # Start SFTP client
        sftp = await s.open_sftp()

        # open remote file
        f = await sftp.open('/etc/ssh/sshd_config','r')
        print(await f.read())
        # seek to position 100
        await f.seek(100)
        # read 20 bytes
        print(await f.read(20))
        # close file
        await f.close()

        # open remote file for write
        f = await sftp.open('hello.txt','w')
        await f.write(b'hello world\n')
        await f.write(b"From localhost\n")
        await f.close()

        # open file in append mode
        f = await sftp.open('hello.txt','a')
        await f.write(b'more data\n')
        await f.write(b"in append mode\n")
        await f.close()

        f = await sftp.open('hello.txt','r')
        print(await f.read())
        await f.close()

        # list files in remote directory
        for path in await sftp.listdir('/var/log'):
            print(path)

        # stat remote file (similar to os.stat)
        st = await sftp.stat("hello.txt")
        print(st)
        
        # change file permission 
        await sftp.chmod('hello.txt',0o600)
        # rename remote file
        await sftp.rename('hello.txt','hello.conf')
        # remove remote file
        await sftp.remove('hello.conf')
        # create remote directory
        await sftp.mkdir("demo")
        await sftp.mkdir("demo2")
        # remove directory
        for p in ("demo","demo2"):
            await sftp.rmdir(p)

        # create remote directory and subdirectories
        p = pathlib.Path("test/test1/test2/test3")
        await sftp.mkdir(p,parents=True)
        await sftp.rmdir(p)
        # remove all the parents
        for x in p.parents:
            if str(x) == ".":
                break
            await sftp.rmdir(x)

        
        # with context manager
        async with await sftp.open("hello.txt","w") as f:
            await f.write(b"hello world\n")
        async with await sftp.open("hello.txt","r") as f:
            print(await f.read())
        await sftp.remove("hello.txt")

        # open file in buffering mode. This reduce number of network calls to the server
        # non buffering
        print("Non buffering write....")
        start = time.time()
        async with await sftp.open("hello.txt","w") as f:
            for x in range(100):
                await f.write(os.urandom(1000))
        assert (await sftp.stat("hello.txt")).st_size == 100000
        print("Non buffering %ss"%(time.time()-start))

        # buffering
        start = time.time()
        async with await sftp.open("hello.txt","w",buffering=True) as f:
            for x in range(100):
                await f.write(os.urandom(1000))
        print("Buffering %ss"%(time.time()-start))

        assert (await sftp.stat("hello.txt")).st_size == 100000
        await sftp.remove("hello.txt")
        
curio.run(main)

```