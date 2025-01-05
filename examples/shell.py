import termios
import tty
import sys

import curio
from ssh import SSHClient

async def main():
    port = 22
    try:
        host = sys.argv[1]
        key = sys.argv[2]
        user,host = host.split("@")
    except Exception:
        print("USAGE: ","python3 shell.py [user@host] [key path]")
        exit(0)
    async with SSHClient() as s:
        await s.connect(host, port)
        # login with public key
        await s.login(user, key=key)
        ch = await s.open_session()
        await ch.run_interactive_shell()

curio.run(main)
    