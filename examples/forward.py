from ssh import SSHClient
import curio
from curio.socket import socket
import socket as pysock


async def copy_data(src, dest):
    # copy data from src to dest
    while True:
        d = await src.recv(1024)
        if not d:
            await src.close()
            if hasattr(dest,'shutdown'):
                await dest.shutdown(pysock.SHUT_RDWR)
            else:
                await dest.close()
            break
        await dest.send(d)


async def main():
    sock = socket()
    sock.bind(("localhost", 8000))
    sock.listen()
    host = "localhost"
    print("listening on localhost:8000")
    port = 22
    tasks = []
    async with SSHClient() as s:
        await s.connect(host, port)
        # login with public key
        await s.login("user", key="/path/to/key")
        while True:
            client, a = await sock.accept()
            chan = await s.open_port_forward("ip-api.com", 80, a[0], a[1])
            t1 = await curio.spawn(copy_data, chan, client)
            t2 = await curio.spawn(copy_data, client, chan)
            print("port forward opeend")
            tasks.append(t1)
            tasks.append(t2)


curio.run(main)
