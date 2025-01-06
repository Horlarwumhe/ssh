import io
import os
import sys
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
        self.sftp = False
        self.timeout = self.client.timeout
        self.tty = self.shell = False

    @classmethod
    def next_id(cls):
        return next(cls.ids_pool)

    @util.timeout
    async def run_command(self, cmd):
        if isinstance(cmd, (list, tuple)):
            cmd = " ".join(cmd)
        if self.type != "session":
            # TODO
            pass
        self.request_event.clear()
        msg = MSG.SSHMsgChannelRequest(
            recipient_channel=self.remote_id, type="exec", want_reply=True, command=cmd
        )
        await self.send_message(msg)
        await self.request_event.wait()
        if not self.request_success:
            raise RuntimeError("Failed to run command")
        self.request_success = None
        self.is_exec = True

    @util.timeout
    async def request_tty(
        self, term="xterm-256color", width=80, height=24, width_pixels=0, height_pixels=0
    ):
        """
        Request a tty for the channel
        """
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
        await self.send_message(msg)
        await self.request_event.wait()
        if not self.request_success:
            raise RuntimeError("Failed to request for tty")
        self.request_success = None
        self.tty = True

    @util.timeout
    async def request_shell(self):
        """
        Request a shell for the channel
        """
        self.request_event.clear()
        msg = MSG.SSHMsgChannelRequest(
            recipient_channel=self.remote_id, type="shell", want_reply=True
        )
        await self.send_message(msg)
        await self.request_event.wait()
        if not self.request_success:
            raise RuntimeError("Failed to request for shell")
        self.request_success = None
        self.shell = True

    @util.timeout
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
        await self.send_message(msg)
        await self.request_event.wait()
        if not self.request_success:
            raise RuntimeError("Failed to open subsystem")
        self.request_success = None
        if name == "sftp":
            self.sftp = True
    @util.check_closed
    async def send(self, data: str | bytes):
        """
        Write data to the channel
        """
        m = MSG.SSHMsgChannelData(recipient_channel=self.remote_id, data=data)
        await self.client.send_message(m)

    @util.check_closed
    async def send_message(self, msg):
        await self.client.send_message(msg)

    def is_active(self):
        if self.eof or self.closed:
            return False
        if self.is_exec:
            return self.exit_code is None
        return True

    async def recv(self, size: int):
        """
        Read data from the channel
        """
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

    async def recv_stderr(self, size: int):
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

    async def stderr(self, n=-1, block=False):
        """
        Read data from the stderr
        """
        if not block:
            return await self.recv_stderr(n)
        data = b""
        n = -1  # n should be -1 to read all data
        while True:
            d = await self.recv_stderr(n)
            data += d
            if d == b"":
                break
        return data

    async def stdout(self, n=-1, block=False):
        """
        Read data from the stdout
        """
        if not block:
            return await self.recv(n)
        data = b""
        n = -1  # n should be -1 to read all data
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
        """
        Check if there is data to read
        """
        return self.data_event.is_set()

    async def close(self):
        """
        Close the channel
        """
        if not self.close_sent:
            await self.send_message(MSG.SSHMsgChannelClose(recipient_channel=self.remote_id))
            self.close_sent = True
        self.closed = True
        await self.data_event.set()
        await self.ext_data_event.set()

    async def set_eof(self):
        self.eof = True
        await self.data_event.set()
        await self.ext_data_event.set()

    def set_exit_code(self, exit):
        self.exit = exit

    async def set_exit_event(self, code):
        self.exit = code
        await self.exit_event.set()

    @property
    def exit_code(self):
        return self.exit
    async def set_request_response(self,value):
        self.request_success = value
        await self.request_event.set()

    @util.check_closed
    async def run_interactive_shell(self):
        """
        Run an interactive shell
        """
        if not self.tty:
            await self.request_tty()
        if not self.shell:
            await self.request_shell()
        try:
            import termios
            import tty
        except ImportError:
            raise ImportError("interactive shell requires termios and tty module")

        async def recv_from_chan():
            try:
                while True:
                    data = await self.recv(2048)
                    if b'\x1b[?1049l' in data:
                        #  soft reset terminal after commands that open alternate screen buffer
                        #  exits. This is a bit of a hack, but it works. vim,nano, screen
                        sys.stdout.write('\033[!p')
                        sys.stdout.flush()
                        pass
                    if not data:
                        break
                    sys.stdout.write(data.decode(errors="replace"))
                    sys.stdout.flush()
            finally:
                await self.close()

        # Adapted from https://github.com/paramiko/paramiko/blob/master/demos/interactive.py
        oldtty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            task = await curio.spawn(recv_from_chan)
            stdin = curio.file.AsyncFile(sys.stdin)
            while True:
                d = await stdin.read(1)
                if not d:
                    break
                if self.closed:
                    break
                await self.send(d.encode())

        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
            await task.cancel()
            try:
                await task.join()
            except Exception:
                pass
        await self.close()
        sys.stdout.write("connection closed\n")


class ChannelError(Channel):
    def __init__(self, err):
        self.err = err
