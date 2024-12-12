import io
import itertools
import os

import curio

import ssh.client

from . import message as MSG

import logging


class Channel:
    ids_pool = iter(range(1, 2 << 31))

    def __init__(self, client, chid=0, remote_id=0):
        self.channel_id = chid
        self.remote_id = remote_id
        self.client = client
        self.type = ""
        self.lock = curio.Lock()
        self.buf = io.BytesIO()
        self.lock2 = curio.Lock()
        self.ext_buf = io.BytesIO()
        self.closed = self.eof = False
        self.exit = None
        self.data_event = curio.Event()
        self.is_exec = False

    @classmethod
    def next_id(cls):
        return next(cls.ids_pool)

    async def run_command(self, cmd):
        if isinstance(cmd, (list, tuple)):
            cmd = " ".join(cmd)
        if self.type != "session":
            # TODO
            pass
        msg = MSG.SSHMsgChannelRequest(
            recipient_channel=self.remote_id, type="exec", want_reply=True, command=cmd
        )
        await self.client.send_message(msg)
        self.is_exec = True

    async def request_tty(self):
        pass

    async def request_shell(self):
        pass

    async def send(self, data: str | bytes):
        if self.closed:
            return
        m = MSG.SSHMsgChannelData(recipient_channel=self.remote_id, data=data)
        await self.client.send_message(m)

    def is_active(self):
        if self.eof or self.closed:
            return False
        if self.is_exec:
            return self.exit_code is None
        return True

    async def recv(self, size: int):
        await self.lock.acquire()
        try:
            data = self.buf.read(size)
            if data == b"" and self.is_active():
                self.data_event.clear()
                # release lock so writer wont block
                await self.lock.release()
                await self.data_event.wait()
                return self.buf.read(size)
            else:
                return data
        finally:
            if self.lock.locked():
                await self.lock.release()

    async def set_data(self, data):
        async with self.lock:
            pos = self.buf.tell()
            self.buf.seek(0,os.SEEK_END)
            self.buf.write(data)
            self.buf.seek(pos)
            await self.data_event.set()

    async def set_ext_data(self, data):
        async with self.lock2:
            pos = self.ext_buf.tell()
            self.ext_buf.seek(0,os.SEEK_END)
            self.ext_buf.write(data)
            self.ext_buf.seek(pos)

    async def stderr(self, n):
        return self.ext_buf.read(n)

    async def stdout(self, n):
        # while True:
        #     data = self.buf.read(n)
        #     if not data and self.exit_code is None:
        #         await curio.sleep(0.2)
        #         continue
        #     return data
        return await self.recv(n)

    async def close(self):
        self.closed = True
        await self.data_event.set()

    async def set_eof(self):
        self.eof = True
        await self.data_event.set()

    def set_exit_code(self, exit):
        self.exit = exit

    @property
    def exit_code(self):
        return self.exit


class ChannelError(Channel):
    def __init__(self, err):
        self.err = err
