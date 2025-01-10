from argparse import ArgumentParser
import getpass
import logging
import os
import pathlib
import sys
import curio
from ssh import SSHClient
from ssh.sftp import SFTP
import resource
import tqdm
import logging
import stat


fdlimit = resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 20
bar_format = "{l_bar} {n_fmt}/{total_fmt} {rate_fmt}{postfix}"
import logging

def main():
    parser = ArgumentParser(prog="pyscp")
    parser.add_argument("src", nargs="+")
    parser.add_argument("dest")
    parser.add_argument("-i", "--identity", help="Private key file")
    parser.add_argument("-p", dest="port", default=22, type=int)
    parser.add_argument("-r", "--recursive", dest="recursive", action="store_true")
    args = parser.parse_args()
    key = args.identity
    if key and not os.path.exists(key):
        sys.stdout.write("%s does not exist. No such file.\n" % key)
        exit(1)
    curio.run(cli_main, args, with_monitor=True)


def gather_all_files(args):
    """
    Returns absolute and relative paths for all files to be copied.
    """
    files = []
    for path in args.src:
        path = pathlib.Path(path)
        if not path.exists():
            sys.stderr.write("No such file or directory %s\n" % path)
            exit(1)
        if path.is_dir() and not args.recursive:
            sys.stderr.write("%s is a directory. Use -r to copy directories.\n" % path)
            exit(1)
        if path.is_file():
            files.append((path,pathlib.Path(path.name)))
        elif path.is_dir():
            # walk if this is a directory
            for p in path.rglob("*"):
                if not p.is_file():
                    continue
                files.append((p,path.name / p.relative_to(path)))
    return files

async def gather_all_remote_files(sftp,path):
        """
        Gather all files from remote path recurisvely.
        """
        result = []
        path = pathlib.Path(path)
        for name,attrs in await sftp.listdir(str(path),attrs=True):
            fullname = path / name
            if stat.S_ISREG(attrs.permissions):
                result.append(fullname)
            elif stat.S_ISDIR(attrs.permissions):
                result.extend(await gather_all_remote_files(sftp,fullname))
        return result

async def copy_from_remote(ssh,path,args):
    """
    Copy files from remote host to local.
    pyscp -r user@host:/path/to/src /path/to/dest
    :path: remote path
    :args: argparse.Namespace
    """
    sftp  = await ssh.open_sftp()
    path = pathlib.Path(path)
    try:
        f = await sftp.stat(str(path))
    except OSError as e:
        sys.stderr.write("%s %s" % (e,args.src[0]))
        exit(1)
    sys.stdout.write("Listing remote files\n")
    if stat.S_ISREG(f.st_mode):
        files = [path]
    elif stat.S_ISDIR(f.st_mode):
        files = await gather_all_remote_files(sftp,path)
    sys.stdout.write("total files %d\n" % len(files))
    tasks = []
    lock = curio.Semaphore(value=fdlimit)
    for f in files:
        file = (f,path.name/f.relative_to(path))
        task = await curio.spawn(copy_file_from_remote(sftp,args.dest,file,lock))
        tasks.append(task)
    for t in tasks:
        try:
            await t.join()
        except curio.errors.TaskError as e:
            print(e)
    


async def copy_file_from_remote(sftp,dest,file,lock):
    try:
        async with lock:
            abspath, relpath = file
            dest = pathlib.Path(dest) / relpath
            dest.parent.mkdir(parents=True,exist_ok=True)
            size = (await sftp.stat(str(abspath))).st_size
            chunck = 31 * 1024  # channel max packet is 32kb
            with tqdm.tqdm(
                bar_format=bar_format,
                total=size,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                miniters=1,
                desc=str(relpath),
            ) as bar:
                async with await sftp.open(str(abspath), "r") as f, curio.aopen(dest,'wb') as src:
                    while True:
                        data = await f.read(chunck)
                        if not data:
                            break
                        await src.write(data)
                        bar.update(len(data))
    except Exception as e:
        sys.stderr.write("error downloading file %s: %s\n"%(abspath,e))

async def copy_to_remote(ssh, path, args):
    """
    copy files from local to remote
    pyscp -r local_dir user@host:/path/to/dest
    dest: remote dest path
    args: argparse.Namespace
    """
    files = gather_all_files(args)
    sftp = await ssh.open_sftp()
    dest = path
    if dest == "":
        dest = "."
    try:
        await sftp.stat(dest)
    except OSError as e:
        if e.args[1] == 2:  # no such file
            try:
                await sftp.mkdir(dest)
            except OSError as e:
                sys.stderr.write("%s %s\n" % (e.args[0], args.dest))
                exit(1)
        else:
            sys.stderr.write("%s %s\n" % (e.args[0], args.dest))
            exit(1)
    tasks = []
    # semaphore for file descriptor limit. To avoid "Too many open files" error.
    fd = curio.Semaphore(value=fdlimit)
    for file in files:
        tasks.append(await curio.spawn(copy_file_to_remote, sftp, dest, file, fd))
    for t in tasks:
        try:
            await t.join()
        except curio.errors.TaskError as e:
            print(e)
    
async def copy_file_to_remote(sftp: SFTP, dest, file, lock):
    async with lock:
        try:
            abspath, relpath = file
            dest = dest / relpath
            await sftp.mkdir(dest.parent, parents=True)
            chunck = 31 * 1024  # channel max packet is 32kb
            with tqdm.tqdm(
                bar_format=bar_format,
                total=abspath.stat().st_size,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                miniters=1,
                desc=str(relpath),
            ) as bar:
                async with await sftp.open(str(dest), "w") as f, curio.aopen(abspath,'rb') as src:
                    while True:
                        data = await src.read(chunck)
                        if not data:
                            break
                        await f.write(data)
                        bar.update(len(data))
        except OSError as e:
            sys.stderr.write("Upload error %s: %s\n" % (relpath, e))



async def cli_main(args):
    # user,host = args.host.split("@")
    port = args.port
    src = set(args.src)  # convert to set to remove duplicate src
    print(args.dest,args.src)
    if "@" in args.dest:
        # dest remote
        to_remote = True
        remote = args.dest
    else:
        to_remote = False
        src = args.src[0]
        remote = src
        if not "@" in src:
            sys.stderr.write("One of src or dest must be remote server")
            exit(1)
        if len(args.src) != 1:
            sys.stderr.write("Only one remote source is supported.\n")
            exit(1)
    try:
        user, host = remote.split("@")
        host, host_path = host.split(":")
    except ValueError:
        sys.stderr.write("Invalid host format. Must be  user@host:/path/\n")
        exit(1)

    async with SSHClient() as ssh:
        await ssh.connect(host, port)
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
        # logging.disable(logging.INFO)
        if to_remote:
            await copy_to_remote(ssh, host_path, args)
        else:
            if not os.path.exists(args.dest) or not os.path.isdir(args.dest):
               sys.stderr.write("Invalid destination path. %s\n"%args.dest)
               exit(1)
            await copy_from_remote(ssh,host_path,args)