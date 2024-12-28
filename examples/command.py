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
        await s.auth_public_key('user',"/path/to/key")
        # or password
        # await s.auth_password("user","pass")
        cmd = await s.run_command("ls /")
        # read 1024 bytes from stdout
        print((await cmd.stdout(1024)).decode())
        # read 1024 bytes from stderr
        print((await cmd.stderr(1024)).decode())
        # print exit code
        cmd = await s.run_command('uname -a')
        print(await cmd.stdout(1024))
        print(cmd.exit_code)
        cmd = await s.run_command("ls /proc")
        while True:
            d = await cmd.stdout(1024)
            if not d:
                break
            print(d.decode())
        print(cmd.exit_code)

        # read 1024 from stderr
        print((await cmd.stderr(1024)).decode())


curio.run(main)
