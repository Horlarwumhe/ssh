import io
import os
import pathlib

import curio

from ssh.sftp.types import *
from ssh.stream import Buffer

nums = iter(range(1, 2 << 32 - 1))


def rand_id():
    return next(nums)


class SFTP:
    def __init__(self, channel):
        self.channel = channel
        self.waiting: dict[int, curio.Event] = {}
        self.responses: dict[int, object] = {}

    async def open(self, file, mode,buffering=False):
        """
        Open a file on the remote server.
        :param file: the file to open
        :param mode: specifies the mode in which the file is opened.

        return: SFTPFile
        """
        flags = 0
        if "r" in mode:
            flags |= SSH_FXF.READ
        if "w" in mode:
            flags |= SSH_FXF.WRITE
            flags |= SSH_FXF.CREAT
            flags |= SSH_FXF.TRUNC
        if "a" in mode:
            flags |= SSH_FXF.WRITE
            flags |= SSH_FXF.CREAT
            flags |= SSH_FXF.APPEND

        attrs = SFTPAttributes()
        r = SSHFXPOPEN(id=rand_id(), filename=file, pflags=flags, attrs=attrs)
        await self.send(r)
        resp = await self.get_response(r.id)
        if isinstance(resp, SSHFXPSTATUS):
            raise OSError("[error %s] %s %s" % (resp.error, resp.message, file))
        return SFTPFile(resp.handle, mode,buffering, self)

    async def mkdir(self, path, mode=0o777, parents=False):
        """
        Create a directory on the remote server.
        :param path: the path of the directory to create
        :param mode: the permissions of the directory
        :param parents: if True, create parent directories as needed. Default is False
        """
        path = pathlib.Path(path)
        if str(path) in ("/", ".", ""):
            return
        if parents:
            await self.mkdir(path.parent, mode, parents=parents)
        r = SSHFXPMKDIR(
            id=rand_id(), path=str(path), attrs=SFTPAttributes(permissions=mode)
        )
        await self.send(r)
        resp = await self.get_response(r.id)
        if isinstance(resp, SSHFXPSTATUS):
            if resp.error == SSH_FXF_STATUS.FAILURE:
                # maybe directory already exists
                pass
            elif resp.error != SSH_FXF_STATUS.OK:
                raise OSError("[error %s] %s %s" % (resp.error, resp.message, path))

    async def listdir(self, path):
        """
        List the contents of a directory on the remote server.
        :param path: the path of the directory to list
        """
        r = SSHFXPOPENDIR(id=rand_id(), path=path)
        await self.send(r)
        resp = await self.get_response(r.id)
        if isinstance(resp, SSHFXPSTATUS):
            raise OSError("[error %s] %s %s" % (resp.error, resp.message, path))
        handle = resp.handle
        r = SSHFXPREADDIR(id=rand_id(), handle=handle)
        await self.send(r)
        resp = await self.get_response(r.id)
        await self.send(SSHFXPCLOSE(id=rand_id(), handle=handle))
        paths = []
        if isinstance(resp, SSHFXPNAME):
            for name in resp.names:
                p = name["filename"]
                if p in (".", ".."):
                    continue
                paths.append(p)
            return paths
        else:
            raise OSError("[error %s] %s %s" % (resp.error, resp.message, path))

    async def stat(self, path: str):
        """
        Get the status of a file on the remote server. This is similar to os.stat
        :param path: the path of the file to stat
        """
        r = SSHFXPSTAT(id=rand_id(), path=path)
        return await self.file_stat(r)

    async def fstat(self, handle: bytes):
        r = SSHFXPFSTAT(id=rand_id(), handle=handle)
        return await self.file_stat(r)

    async def file_stat(self, msg):
        await self.send(msg)
        resp = await self.get_response(msg.id)
        if isinstance(resp, SSHFXPATTRS):
            attrs = resp.attrs
            return os.stat_result(
                (
                    attrs.permissions,
                    0, # st_ino not sent by server
                    0, # st_dev not sent by server
                    0, # st_nlink not sent by server
                    attrs.uid,
                    attrs.gid,
                    attrs.size,
                    attrs.atime,
                    attrs.mtime,
                    attrs.mtime,
                )
            )
        path = msg.path if hasattr(msg, "path") else ""
        raise OSError("[error %s] %s %s" % (resp.error, resp.message, path))

    async def remove(self, filename):
        """
        Remove a file on the remote server.
        :param filename: the path of the file to remove
        """
        r = SSHFXPREMOVE(id=rand_id(), filename=filename)
        await self.send(r)
        resp = await self.get_response(r.id)
        if resp.error != SSH_FXF_STATUS.OK:
            raise OSError("[error %s] %s %s" % (resp.error, resp.message, filename))

    async def rmdir(self, path):
        """
        Remove a directory on the remote server.
        :param path: the path of the directory to remove
        """
        r = SSHFXPRMDIR(id=rand_id(), path=str(path))
        await self.send(r)
        resp = await self.get_response(r.id)
        if resp.error != SSH_FXF_STATUS.OK:
            raise OSError("[error %s] %s %s" % (resp.error, resp.message, path))

    async def rename(self, oldpath, newpath):
        """
        Rename a file on the remote server.
        :param oldpath: the old path of the file
        :param newpath: the new path of the file
        """
        r = SSHFXPRENAME(id=rand_id(), oldpath=oldpath, newpath=newpath)
        await self.send(r)
        resp = await self.get_response(r.id)
        if resp.error != SSH_FXF_STATUS.OK:
            raise OSError("[error %s] %s %s" % (resp.error, resp.message, oldpath))

    async def send(self, message):
        if hasattr(message, "id"):
            self.waiting[message.id] = curio.Event()
        data = int.to_bytes(len(bytes(message)), 4, "big") + bytes(message)
        await self.channel.send(data)

    async def read_response(self):
        size = int.from_bytes(await self.channel.recv(4))
        data = b""
        while len(data) < size:
            data += await self.channel.recv(size - len(data))
        type = data[0]
        return HANDLERS[type].parse(Buffer(data))

    async def get_response(self, id):
        await self.waiting[id].wait()
        return self.responses.pop(id)

    async def read_incoming_responses(self):
        while True:
            resp = await self.read_response()
            self.responses[resp.id] = resp
            await self.waiting[resp.id].set()

    async def init(self):
        r = SSHFXPINIT(version=3, extensions={})
        await self.send(r)
        resp = await self.read_response()
        assert resp.version == 3, "3 != %s" % resp.version
        await curio.spawn(self.read_incoming_responses)


class SFTPFile:
    max_read = 16 * 1024  # 16kb
    buffer_size = io.DEFAULT_BUFFER_SIZE

    def __init__(self, handle, mode,buffering=False, sftp: SFTP | None =None):
        self.handle = handle
        self.offset = 0
        self.buffering = buffering
        self.sftp = sftp
        self.mode = mode
        self.closed = False
        self.buffer = io.BytesIO()

    async def read(self, size=None):
        """
        Read data from the file.
        """
        if self.closed:
            raise OSError("file is closed")
        if "r" not in self.mode:
            raise OSError("file not opened for reading")
        if size is None:
            size = self.max_read
        r = SSHFXPREAD(
            id=rand_id(), handle=self.handle, offset=self.offset, length=size
        )
        await self.sftp.send(r)
        resp = await self.sftp.get_response(r.id)
        if isinstance(resp, SSHFXPSTATUS):
            if resp.error == SSH_FXF_STATUS.EOF:
                return b""
            raise OSError("[error %s] %s" % (resp.error, resp.message))
        self.offset += len(resp.data)
        return resp.data

    async def write(self, data):
        """
        Write data to the file.
        """
        if self.closed:
            raise OSError("file is closed")
        if "w" not in self.mode and "a" not in self.mode:
            raise OSError("file not opened for writing")
        self.buffer.write(data)
        if not self.buffering or (self.buffering and self.buffer.tell() >= self.buffer_size):
            await self.do_write()
        return len(data)
    
    @property
    def writable(self):
        return "w" in self.mode or "a" in self.mode

    async def do_write(self):
        data = self.buffer.getvalue()
        if not data:
            return
        self.buffer = io.BytesIO()
        r = SSHFXPWRITE(id=rand_id(), handle=self.handle, offset=self.offset, data=data)
        self.offset += len(data)
        await self.sftp.send(r)
        resp = await self.sftp.get_response(r.id)
        if isinstance(resp, SSHFXPSTATUS):
            if resp.error != SSH_FXF_STATUS.OK:
                raise OSError("[error %s] %s" % (resp.error, resp.message))

    async def flush(self):
        """
        Flush the file.
        """
        if self.writable and self.buffering:
            await self.do_write()

    async def close(self):
        """
        Close the file.
        """
        if self.closed:
            return 
        await self.flush()
        await self.sftp.send(SSHFXPCLOSE(id=rand_id(), handle=self.handle))
        self.closed = True

    async def seek(self, pos, whence=os.SEEK_SET):
        """
        Change the file position. similar to os.lseek.
        :param pos: the new position
        :param whence: the reference point for the new position
        """
        if self.writable:
            await self.flush()
        if whence == os.SEEK_SET:
            self.offset = pos
        elif whence == os.SEEK_CUR:
            self.offset += pos
        elif whence == os.SEEK_END:
            size = (await self.sftp.fstat(self.handle)).st_size
            self.offset = size + pos
        else:
            raise ValueError("invalid whence (%s, should be 0, 1 or 2)" % whence)
        return self.offset

    def tell(self):
        """
        Get the current file position.
        """
        return self.offset

    
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
