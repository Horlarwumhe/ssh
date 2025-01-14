import getpass
import logging
import os
import socket as pysock
import sys
from argparse import ArgumentParser

import curio
from curio import socket

from ssh import SSHClient


def main():
    parser = ArgumentParser(prog="pyssh")
    parser.add_argument("host", help="host to connect to. format is user@host")
    parser.add_argument("-p", "--port", help="port to connect to", default=22, type=int)
    parser.add_argument(
        "-i", "--identity", help="private key to use for authentication"
    )
    parser.add_argument("-v", "--verbose", help="verbose output", action="store_true")
    parser.add_argument("-c", "--command", help="command to execute")
    parser.add_argument("-x", help="same as -c, for compatiblity with OpenSSH.")
    parser.add_argument(
        "-L",
        "--local-forward",
        help="local port forwarding. [local]:localport:dest:destport",
    )
    parser.add_argument("-T",help= "disable pseudo-tty allocation", action="store_true")
    args = parser.parse_args()
    try:
        args.host.split("@")
    except ValueError:
        print("invalid host format. pyssh user@host")
        exit(1)
    key = args.identity
    if key and not os.path.exists(key):
        sys.stdout.write("%s does not exist. No such file.\n" % key)
        exit(1)
    if args.local_forward:
        try:
            _, port, _, remote_port = args.local_forward.split(":")
            port, remote_port = int(port), int(remote_port)
        except ValueError:
            sys.stderr.write( "Bad local forwarding specification %s\n" % args.local_forward)
            exit(1)
    curio.run(cli_main, args)


async def setup_port_forward(args, ssh: SSHClient):
    local, port, remote, remote_port = args.local_forward.split(":")
    sock = setup_socket(local, int(port))
    tasks = []
    try:
        while True:
            client, a = await sock.accept()
            try:
                chan = await ssh.open_port_forward(
                    remote, int(remote_port), a[0], int(a[1])
                )
            except Exception as e:
                sys.stderr.write("\r\n%s\r\n" % str(e))
                await client.close()
                continue
            tasks.append(await curio.spawn(copy_data, client, chan))
            tasks.append(await curio.spawn(copy_data, chan, client))
    except curio.errors.TaskCancelled:
        pass
    finally:
        if sock:
            await sock.close()
        for task in tasks:
            await task.cancel()
            try:
                await task.join()
            except curio.task.TaskError:
                pass


async def copy_data(src, dest):
    while True:
        data = await src.recv(2048)
        if not data:
            break
        await dest.send(data)
    if hasattr(dest, "shutdown"):
        try:
            await dest.shutdown(pysock.SHUT_RDWR) # socket
        except OSError:
            pass
    else:
        await dest.close()  # channel
    await src.close()


async def recv_from_stdout(chan):
    while True:
        data = await chan.stdout()
        if not data:
            await chan.close()
            break
        sys.stdout.write(data.decode(errors="replace"))


async def recv_from_stderr(chan):
    while True:
        data = await chan.stderr()
        if not data:
            await chan.close()
            break
        sys.stderr.write(data.decode(errors="replace"))


def setup_socket(host, port):
    sock = socket.socket()
    sock.setsockopt(pysock.SOL_SOCKET, pysock.SO_REUSEADDR, True)
    sock.bind((host, port))
    sock.listen()
    return sock


async def cli_main(args):
    user, host = args.host.split("@")
    async with SSHClient() as ssh:
        if args.verbose:
            logging.basicConfig(level=logging.DEBUG)
        await ssh.connect(host, args.port)
        use_password = True
        if args.identity:
            try:
                await ssh.login(user, key=args.identity)
                use_password = False
            except Exception as e:
                sys.stdout.write("login failed: %s\n" % e)
        if use_password:
            for _ in range(3):
                try:
                    passwd = getpass.getpass("password for %s@%s: " % (user, host))
                    await ssh.login(user, password=passwd)
                    break
                except Exception as e:
                    sys.stdout.write("login failed: %s\n" % e)
            else:
                sys.stdout.write("login failed:\n")
                exit(1)
        if args.command or args.x:
            cmd = await ssh.run_command(args.command or args.x)
            t1 = await curio.spawn(recv_from_stdout, cmd)
            t2 = await curio.spawn(recv_from_stderr, cmd)
            code = await cmd.wait()
            await t1.join()
            await t2.join()
            exit(code)
        task = None
        if args.local_forward:
            task = await curio.spawn(setup_port_forward, args, ssh)
        session = await ssh.open_session()
        # disable logging in shell
        logging.disable(level=logging.INFO)
        try:
            await session.run_interactive_shell(tty=not args.T)
        except Exception as e:
            print(e)
            exit(1)
        if task:
            await task.cancel()
            try:
                await task.join()
            except curio.errors.TaskError:
                pass


if __name__ == "__main__":
    main()
