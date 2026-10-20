import getpass
import logging
import os
import socket as pysock
import sys
from argparse import ArgumentParser
import curio
from curio import socket
import random

from ssh import algo
from ssh import SSHClient
from ssh.exc import AuthenticationError

def main():
    parser = ArgumentParser(prog="pyssh")
    if "-Q" in sys.argv:
            parser.add_argument("-Q", help="Queries for the algorithms supported",
                    choices=["kex", "cipher", "mac", "key", "help"])
            args,_ = parser.parse_known_args()
            show_algorithms(args.Q)
            exit(0)
    parser.add_argument("host", help="host to connect to. format is user@host")
    parser.add_argument("-p", "--port", help="port to connect to", default=22, type=int)
    parser.add_argument(
        "-i", "--identity", help="private key to use for authentication"
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="verbose output")
    parser.add_argument("-c", "--command", help="command to execute")
    parser.add_argument("-x", help="same as -c, for compatiblity with OpenSSH.")
    parser.add_argument(
        "-L",
        "--local-forward",
        help="local port forwarding. [local]:localport:dest:destport",
    )
    parser.add_argument("-T", help="disable pseudo-tty allocation", action="store_true")
    parser.add_argument('--proxy',help="use socks5 proxy to connect. format is host:port")
    parser.add_argument("--kex", help="preferred key exchange algorithm",choices=list(SSHClient.KEX_ALGOS.keys())+["random"]),
    parser.add_argument("--cipher",help="preferred encryption cipher algorithm",choices=list(SSHClient.ENCRYPTION_ALGOS.keys())+["random"]),
    parser.add_argument("--mac",help="preferred MAC algorithm",choices=list(SSHClient.MAC_ALGOS.keys())+["random"]),
    parser.add_argument("--hostkey",help="preferred server host key algorithm",choices=list(SSHClient.HOST_KEY_ALGOS.keys())+["random"])
    parser.add_argument(
        "--algo",
        action="append",
        nargs=2,
        metavar=("TYPE", "NAME"),
        help="set preferred algorithm. TYPE is one of: kex, cipher, mac, hostkey. "
             "Can be specified multiple times.",
    )
    parser.add_argument("-Q", help="Queries for the algorithms supported. Supported values: kex, cipher, mac, key, all, help", choices=["kex", "cipher", "mac", "key", "all", "help"])
    if "GIT_SSH_COMMAND" in os.environ:
        # host cmd
        host,cmd = sys.argv[-2],sys.argv[-1]
        sys.argv[-2] = cmd
        sys.argv[-1] = host
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
        data = await chan.stdout(1024)
        if not data:
            break

        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

async def recv_from_stderr(chan):
    while True:
        data = await chan.stderr(1024)
        if not data:
            break
        sys.stderr.buffer.write(data)
        sys.stderr.buffer.flush()

async def recv_from_stdin(chan):
    stdin = curio.file.AsyncFile(sys.stdin.buffer.raw)
    while True:
        data = await stdin.read(1024)
        if not data:
            break
        await chan.send(data)

def setup_socket(host, port):
    sock = socket.socket()
    sock.setsockopt(pysock.SOL_SOCKET, pysock.SO_REUSEADDR, True)
    sock.bind((host, port))
    sock.listen()
    return sock


def show_algorithms(algo_type):
    s = SSHClient
    text = ""
    if algo_type == "cipher":
        text = list(s.ENCRYPTION_ALGOS.keys())
        text = map(lambda x: f"{x}(default)**" if x == s.preferred_encryption_algo else x, text)
    if algo_type == "kex":
        text = list(s.KEX_ALGOS.keys())
        text = map(lambda x: f"{x}(default)**" if x == s.preferred_kex_algo else x, text)
    if algo_type == "mac":
        text = list(s.MAC_ALGOS.keys())
        text = map(lambda x: f"{x}(default)**" if x == s.preferred_mac_algo else x, text)
    if algo_type == "key":
        text = list(s.HOST_KEY_ALGOS.keys())
        text = map(lambda x: f"{x} (default)**" if x == s.preferred_server_host_key_algo else x, text)
    print("Supported %s:" % algo_type)
    for algo in text:
        print("  %s" % algo)
    print("**default if supported by the server")


def set_preferred_algos(args):
    def resolve(value, algos):
        if value == "random":
            return random.choice(list(algos.keys()))
        return value

    if args.hostkey:
        SSHClient.preferred_server_host_key_algo = resolve(args.hostkey, algo.HOST_KEY_ALGOS)
    if args.kex:
        SSHClient.preferred_kex_algo = resolve(args.kex, algo.KEX_ALGOS)
    if args.cipher:
        SSHClient.preferred_encryption_algo = resolve(args.cipher, algo.ENCRYPTION_ALGOS)
    if args.mac:
        SSHClient.preferred_mac_algo = resolve(args.mac, algo.MAC_ALGOS)

async def cli_main(args):
    user, host = args.host.split("@")
    proxy = args.proxy
    set_preferred_algos(args)
    
    async with SSHClient(proxy=proxy) as ssh:
        if args.verbose:
            level = {1: logging.INFO, 2: logging.DEBUG}.get(args.verbose, logging.DEBUG)
            setup_logging(level)
        await ssh.connect(host, args.port)
        use_password = True
        if args.identity:
            try:
                await ssh.login(user, key=args.identity)
                use_password = False
            except AuthenticationError as e:
                sys.stdout.write("login failed: %s\n" % e)
        else:
            # try "none"
            try:
                await ssh.login(user)
                use_password = False
            except AuthenticationError as e:
                pass
        if use_password:
            for _ in range(3):
                try:
                    passwd = getpass.getpass("password for %s@%s: " % (user, host))
                    await ssh.login(user, password=passwd)
                    break
                except AuthenticationError as e:
                    sys.stdout.write("login failed: %s\n" % e)
            else:
                sys.stdout.write("login failed:\n")
                exit(1)
        if args.local_forward:
            task = await curio.spawn(setup_port_forward, args, ssh)
        if args.command or args.x:
            cmd = await ssh.run_command(args.command or args.x)
            t1 = await curio.spawn(recv_from_stdout, cmd)
            t2 = await curio.spawn(recv_from_stderr, cmd)
            t3 = await curio.spawn(recv_from_stdin,cmd)
            code = await cmd.wait()
            await t1.join()
            await t2.join()
            await t3.cancel()
            try:
                await t3.join()
            except curio.errors.TaskError:
                pass
            await cmd.close()
            exit(code)
        task = None
        session = await ssh.open_session()
        # disable logging in shell
        logging.disable(level=logging.CRITICAL)
        try:
            code = await session.run_interactive_shell(tty=not args.T)
        except Exception as e:
            print(e)
            exit(1)
        if task:
            await task.cancel()
            try:
                await task.join()
            except curio.errors.TaskError:
                pass
        sys.stdout.write("connection to %s closed\n"%ssh.peer)
        exit(code)


if __name__ == "__main__":
    main()
