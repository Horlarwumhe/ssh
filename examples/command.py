from ssh import SSHClient
import curio
import logging


# logging.basicConfig(level=logging.DEBUG)
async def main():
    host = "localhost"
    port = 22
    async with SSHClient() as s:
        await s.connect(host, port)
        # login with public key
        await s.login('user',key="/path/to/key")
        # or password
        # await s.login("user","pass")
        cmd = await s.run_command("ls /")
        print((await cmd.stdout()).decode())
        print((await cmd.stderr()).decode())
        # print exit code
        cmd = await s.run_command('uname -a')
        print(await cmd.stdout())
        print(cmd.exit_code)
        cmd = await s.run_command("ls /proc")
        while True:
            d = await cmd.stdout()
            if not d:
                break
            print(d.decode())
        print(cmd.exit_code)

        print((await cmd.stderr()).decode())


curio.run(main)
