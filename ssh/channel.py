import io
import logging
import os
import sys
from typing import NoReturn

import curio

from ssh import util

from . import message as MSG


class Channel:
    ids_pool = iter(range(1, 2 << 31))
    window_size = 2 << 31 - 1 # 2GB

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
        self.sent_bytes = self.recv_bytes = 0
    @classmethod
    def next_id(cls):
        return next(cls.ids_pool)

    @util.timeout
    async def run_command(self, cmd: str | list[str]):
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
    async def request_shell(self) -> None:
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
    async def request_subsystem(self, name: str) -> None:
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

    async def request_env(self, name: str, value: str) -> None:
        """
        Request to set an environment variable for the channel
        param name: name of the environment variable
        param value: value of the environment variable
        """
        self.request_event.clear()
        msg = MSG.SSHMsgChannelRequest(
            recipient_channel=self.remote_id,
            type="env",
            want_reply=True,
            name=name,
            value=value,
        )
        await self.send_message(msg)
        await self.request_event.wait()
        if not self.request_success:
            raise RuntimeError("Failed to set environment variable")
        self.request_success = None

    async def setenv(self, env: dict):
        """
        Set multiple environment variables for the channel
        param env: dictionary of environment variables
        """
        for k, v in env.items():
            await self.request_env(k, v)

    @util.check_closed
    async def send(self, data: bytes) -> None:
        """
        Write data to the channel
        """
        m = MSG.SSHMsgChannelData(recipient_channel=self.remote_id, data=data)
        await self.client.send_message(m)

    @util.check_closed
    async def send_message(self, msg: MSG.SSHMessage):
        await self.client.send_message(msg)

    def is_active(self):
        if self.eof or self.closed:
            return False
        if self.is_exec:
            return self.exit_code is None
        return True

    async def recv(self, size: int) -> bytes:
        """
        Read data from the channel
        """
        await self.lock.acquire()
        try:
            data = self.buf.read(size)
            if data == b"" and self.is_active():
                self.data_event.clear()
                # clear memory
                self.buf = io.BytesIO()
                # release lock so writer wont block
                await self.lock.release()
                await self.data_event.wait()
                return self.buf.read(size)
            return data
        finally:
            if self.lock.locked():
                await self.lock.release()

    async def recv_stderr(self, size: int) -> bytes:
        await self.lock2.acquire()
        try:
            data = self.ext_buf.read(size)
            if data == b"" and self.is_active():
                self.ext_data_event.clear()
                # release lock so writer wont block
                await self.lock2.release()
                await self.ext_data_event.wait()
                return self.ext_buf.read(size)
            return data
        finally:
            if self.lock2.locked():
                await self.lock2.release()

    async def stderr(self, n=-1, block=False) -> bytes:
        """
        Read data from the stderr
        """
        return await self._read_data(self.recv_stderr, n, block)

    async def stdout(self, n=-1, block=False) -> bytes:
        """
        Read data from the stdout
        """
        return await self._read_data(self.recv, n, block)
    
    async def _read_data(self,fn, n: int,block: bool) -> bytes:
        if not block:
            return await fn(n)
        data = b""
        n = -1  # n should be -1 to read all data
        while True:
            d = await fn(n)
            data += d
            if d == b"":
                break
        return data

    async def wait(self) -> int:
        """
        If the channel is a command, wait for the command to finish. similar to wait in subprocess
        """
        if not self.is_exec:
            return
        await self.exit_event.wait()
        return self.exit_code

    async def set_data(self, data: bytes) -> None:
        async with self.lock:
            pos = self.buf.tell()
            self.buf.seek(0, os.SEEK_END)
            self.buf.write(data)
            self.buf.seek(pos)
            self.recv_bytes += len(data)
            await self.data_event.set()
        await self.check_window_size()

    async def set_ext_data(self, data: bytes) -> None:
        async with self.lock2:
            pos = self.ext_buf.tell()
            self.ext_buf.seek(0, os.SEEK_END)
            self.ext_buf.write(data)
            self.ext_buf.seek(pos)
            self.recv_bytes += len(data)
            await self.ext_data_event.set()
        await self.check_window_size()
        
    
    async def check_window_size(self) -> None:
        if self.recv_bytes >= self.window_size:
            # This size is mostly reached when using sftp/scp.
            logging.info('window size(%s) reached, adjusting....'%self.window_size)
            await self.client.send_message(MSG.SSHMsgWindowAdjust(recipient_channel=self.remote_id,size=self.window_size))
            self.recv_bytes = 0

    def has_data(self) -> bool:
        """
        Check if there is data to read
        """
        return self.data_event.is_set()

    async def close(self) -> None:
        """
        Close the channel
        """
        if not self.close_sent:
            try:
                await self.send_message(MSG.SSHMsgChannelClose(recipient_channel=self.remote_id))
            except OSError:
                # socket related errors
                pass
            self.close_sent = True
        self.closed = True
        await self.data_event.set()
        await self.ext_data_event.set()

    async def set_eof(self) -> None:
        self.eof = True
        await self.data_event.set()
        await self.ext_data_event.set()

    def set_exit_code(self, exit: int) -> None:
        self.exit = exit

    async def set_exit_event(self, code: int) -> None:
        self.exit = code
        await self.exit_event.set()

    @property
    def exit_code(self):
        return self.exit
    async def set_request_response(self,value):
        self.request_success = value
        await self.request_event.set()

    @util.check_closed
    async def run_interactive_shell(self, tty=True) -> int:
        """
        Run an interactive shell
        """
        if not self.tty and tty:
            await self.request_tty()
        if not self.shell:
            await self.request_shell()
        try:
            import termios
            import tty as libtty
        except ImportError:
            raise ImportError("interactive shell requires termios and tty module")
        
        async def recv_from_stderr():
            while True:
                data = await self.stderr()
                if not data:
                    await self.close()
                    break
                sys.stderr.write(data.decode(errors="replace"))
        
        async def recv_from_chan():
            try:
                while True:
                    data = await self.recv(2048)
                    if b'\x1b[?1049l' in data:
                        #  soft reset terminal after commands that open alternate screen buffer
                        #  exits. This is a bit of a hack, but it works. vim,nano, screen
                        sys.stdout.write('\033[!p')
                        sys.stdout.flush()
                    if not data:
                        break
                    sys.stdout.write(data.decode(errors="replace"))
                    # the above hack doesnt work for apt, and probably some other commands.
                    # This might be overkill, but it is only solution for now.
                    sys.stdout.write("\033[!p")
                    sys.stdout.flush()
            finally:
                await self.close()

        # Adapted from https://github.com/paramiko/paramiko/blob/master/demos/interactive.py
        if tty:
            oldtty = termios.tcgetattr(sys.stdin)
            try:
                libtty.setraw(sys.stdin.fileno())
                libtty.setcbreak(sys.stdin.fileno())
                task = await curio.spawn(recv_from_chan)
                stdin = curio.file.AsyncFile(sys.stdin)
                while True:
                    d = await stdin.read(1)
                    if not d:
                        break
                    if self.closed:
                        break
                    await self.send(d.encode())
            except Exception as e:
                sys.stdout.write("exception: %s\n" % e)
                sys.stdout.flush()
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
                await self.close()
                await task.cancel()
                try:
                    await task.join()
                except curio.errors.TaskError:
                    pass
        else:
            # No tty, recieve from both stdout and stderr
            task = await curio.spawn(recv_from_chan)
            task2 = await curio.spawn(recv_from_stderr)
            await task2.join()
            await task.join()
        return self.exit_code

class ChannelError(Channel):
    def __init__(self, err):
        self.err = err
