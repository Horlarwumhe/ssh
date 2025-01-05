import os
from ssh import SSHClient
import curio
import logging
import time
import pathlib
# logging.basicConfig(level=logging.DEBUG)
async def main():
    host = 'localhost'
    port = 22
    async with SSHClient() as s:
        await s.connect(host,port)
        #login with public key
        await s.login("user", key="/path/to/key")

        # or password
        # await s.login('user','pass')

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
