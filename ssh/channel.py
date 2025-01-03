import io
import os
from ssh import util
import curio


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
        self.ext_data_event = curio.Event()
        self.exit_event = curio.Event()
        self.is_exec = False
        self.request_event = curio.Event()
        self.request_success = None
        self.close_sent = False

    @classmethod
    def next_id(cls):
        return next(cls.ids_pool)

    @util.check_closed
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
        await self.request_event.wait()
        self.is_exec = True

    @util.check_closed
    async def request_tty(
        self, term="vt100", width=80, height=24, width_pixels=0, height_pixels=0
    ):
        self.request_event.clear()
        msg = MSG.SSHMsgChannelRequest(
            recipient_channel=self.remote_id,
            type="pty-req",
            want_reply=True,
            width_char=width,
            heigth_char=height,
            width_pixel=width_pixels,
            heigth_pixel=height_pixels,
            term_env_var=term,
        )
        await self.client.send_message(msg)
        await self.request_event.wait()
        if not self.request_success:
            raise RuntimeError("Failed to request for tty")
        self.request_success = None

    @util.check_closed
    async def request_shell(self):
        self.request_event.clear()
        msg = MSG.SSHMsgChannelRequest(
            recipient_channel=self.remote_id, type="shell", want_reply=True
        )
        await self.client.send_message(msg)
        await self.request_event.wait()
        if not self.request_success:
            raise RuntimeError("Failed to request for shell")
        self.request_success = None

    @util.check_closed
    async def request_subsystem(self, name):
        """
        Request a subsystem for the channel
        param name: name of the subsystem
        """
        self.request_event.clear()
        msg = MSG.SSHMsgChannelRequest(
            recipient_channel=self.remote_id,
            type="subsystem",
            want_reply=True,
            subsystem_name=name,
        )
        await self.client.send_message(msg)
        await self.request_event.wait()
        if not self.request_success:
            raise RuntimeError("Failed to open subsystem")
        self.request_success = None
        if name == "sftp":
            self.sftp = True

    @util.check_closed
    async def send(self, data: str | bytes):
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

    async def recv_stderr(self,size: int):

        await self.lock2.acquire()
        try:
            data = self.ext_buf.read(size)
            if data == b"" and self.is_active():
                self.ext_data_event.clear()
                # release lock so writer wont block
                await self.lock2.release()
                await self.ext_data_event.wait()
                return self.ext_buf.read(size)
            else:
                return data
        finally:
            if self.lock2.locked():
                await self.lock2.release()

    async def stderr(self, n=-1,block=False):
        """
        Read data from the stderr
        """
        if not block:
            return await self.recv_stderr(n)
        data = b""
        n = -1 # n should be -1 to read all data
        while True:
            d = await self.recv_stderr(n)
            data += d
            if d == b"":
                break
        return data

    async def stdout(self, n=-1,block=False):
        """
        Read data from the stdout
        """
        if not block:
            return await self.recv(n)
        data = b""
        n = -1 # n should be -1 to read all data
        while True:
            d = await self.recv(n)
            data += d
            if d == b"":
                break
        return data

    async def wait(self):
        """
        If the channel is a command, wait for the command to finish. similar to wait in subprocess
        """
        if not self.is_exec:
            return
        await self.exit_event.wait()
        return self.exit_code
    

    async def set_data(self, data):
        async with self.lock:
            pos = self.buf.tell()
            self.buf.seek(0, os.SEEK_END)
            self.buf.write(data)
            self.buf.seek(pos)
            await self.data_event.set()

    async def set_ext_data(self, data):
        async with self.lock2:
            pos = self.ext_buf.tell()
            self.ext_buf.seek(0, os.SEEK_END)
            self.ext_buf.write(data)
            self.ext_buf.seek(pos)
            await self.ext_data_event.set()

    def has_data(self):
        return self.data_event.is_set()
    
    async def close(self):
        self.closed = True
        if not self.close_sent:
            await self.client.send_message(MSG.SSHMsgChannelClose(recipient_channel=self.remote_id))
            self.close_sent = True
        await self.data_event.set()
        await self.ext_data_event.set()

    async def set_eof(self):
        self.eof = True
        await self.data_event.set()
        await self.ext_data_event.set()

    def set_exit_code(self, exit):
        self.exit = exit

    async def set_exit_event(self,code):
        self.exit = code
        await self.exit_event.set()

    @property
    def exit_code(self):
        return self.exit
    async def set_request_response(self,value):
        self.request_success = value
        await self.request_event.set()


class ChannelError(Channel):
    def __init__(self, err):
        self.err = err
