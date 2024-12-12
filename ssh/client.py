import logging
import os
from itertools import chain

import curio

from ssh import util
from ssh.channel import Channel, ChannelError
from ssh.stream import Buffer

from . import encryption as enc
from . import kex, key, mac
from .message import *
from .packet import Connection

DEBUG = logging.DEBUG
INFO = logging.INFO


class SSHClient:
    version = "SSH-2.0-to_be_determined"
    preferred_kex_algo = ""
    available_kex_algo: dict[str, kex.DHKex] = {
        "diffie-hellman-group14-sha256": kex.DHGroup14SHA256,
        "diffie-hellman-group16-sha512": kex.DHGroup16SHA512,
        "curve25519-sha256": kex.Curve25519,
        "diffie-hellman-group14-sha1": kex.DHGroup14SHA1,
        "diffie-hellman-group1-sha1": kex.DHGroup1SHA1,
        "diffie-hellman-group18-sha512": kex.DHGroup18SHA512,
    }
    preferred_encryption_algo = ""
    available_encryption_algo: dict[str, enc.AES] = {
        "aes256-ctr": enc.AESCTR256,
        "aes128-ctr": enc.AESCTR128,
        "aes192-ctr": enc.AESCTR192,
    }
    preferred_mac_algo = ""
    available_mac_algo: dict[str, mac.HMAC] = {
        "hmac-sha2-256": mac.HMACSHA256,
        "hmac-sha2-512": mac.HMACSHA512,
        "hmac-sha1": mac.HMACSHA1,
    }
    preferred_server_host_key_algo = ()
    available_server_host_key_algo: dict[str, callable] = {
        "rsa-sha2-512": key.RSAKey,
        "rsa-sha2-256": key.RSAKey,
    }

    def __init__(self) -> None:
        self.sock = Connection()
        self.logger = logging.getLogger("ssh")
        self.kex_algo = None
        self.server_host_key_algo = None
        self.encryption_algo = None
        self.mac_algo = None
        self.compression_algo = None
        self.kex_init = None
        self.server_kex_init = None
        self.kex_result = None
        self.session_id = None
        self.tasks = []
        self.events: dict[int, curio.Event] = {}
        self.close_event = curio.Event()
        self.channel_events: dict[int, curio.Event] = {}
        self.channels = {}
        self.task_event = curio.Event()
        self.auth_event = curio.Event()
        self.authenticated = False
        self.server_closed = False
        self.close_reason = ''

        self.message_handlers = {
            SSHMsgDisconnect.opcode: self.handle_message_disconnect,
            SSHMsgChannelData.opcode: self.handle_channel_data,
            SSHMsgChannelClose.opcode: self.handle_channel_message,
            SSHMsgChannelEOF.opcode: self.handle_channel_message,
            SSHMsgChannelSuccess.opcode: self.handle_channel_message,
            SSHMsgChannelFailure.opcode: self.handle_channel_message,
            SSHMsgChannelRequest.opcode: self.handle_channel_message,
            SSHMsgChannelExtendData.opcode: self.handle_channel_data,
            SSHMsgChannelOpenConfirmation.opcode: self.handle_channel_open,
            SSHMsgChannelOpenFailure.opcode: self.handle_channel_open,
            SSHMsgUserauthFailure.opcode: self.handle_auth_response,
            SSHMsgUserauthSuccess.opcode: self.handle_auth_response
        }

    async def connect(self, host, port, start_kex=False):
        await self.sock.connect(host, port)
        while True:
            line = await self.sock.readline()
            if line.startswith(b"SSH-"):
                self.remote_version = line.decode().strip()
                self._log(
                    logging.INFO, " setting remote_version %s" % self.remote_version
                )
                break
            self.logger.info("got %s" % line)
            if not line:
                raise ConnectionResetError("server diconnnected")
        await self.sock.send(self.version.encode() + b"\r\n")
        if start_kex:
            await self.start_kex()
            self.tasks.append(await curio.spawn(self.get_packets))

    async def get_packets(self):
        self.tasks.append(await curio.spawn(self.clean_up_tasks))
        while True:
            packet = await self.sock.read_packet()
            msg = HANDLERS[packet.opcode].parse(Buffer(packet.payload))
            # await curio.sleep(0.1)
            if msg.opcode in self.events:
                self.logger.debug("Found message in events %s", msg)
                ev = self.events.pop(msg.opcode)
                await ev.set()
            fn = self.message_handlers.get(msg.opcode)
            if fn:
                self.logger.log(DEBUG, "calling handler %s", fn)
                self.tasks.append(await curio.spawn(fn, msg))
            else:
                self.logger.log(logging.INFO, "handler not found %s", msg)

    # async def read_incoming

    # async def run(self):
    #     async with trio.open_nursery() as nursery:
    #         nursery.start_soon(self.loop, "a")
    #         nursery.start_soon(self.loop, "b")

    async def start_kex(self):
        req = SSHMsgKexInit(
            cookie=os.urandom(16),
            kex_algo=list(self.available_kex_algo.keys()),
            server_host_key_algo=list(self.available_server_host_key_algo),
            encryption_algo_client_to_server=list(
                self.available_encryption_algo.keys()
            ),
            encryption_algo_server_to_client=list(
                self.available_encryption_algo.keys()
            ),
            mac_algo_client_to_server=list(self.available_mac_algo.keys()),
            mac_algo_server_to_client=list(self.available_mac_algo.keys()),
            compression_algo_client_to_server=list(("none",)),
            compression_algo_server_to_client=list(("none",)),
            languages_client_to_server=list(),
            languages_server_to_client=list(),
            first_kex_packet_follows=False,
        )

        if self.preferred_kex_algo:
            req.kex_algo.insert(0, self.preferred_kex_algo)
        if self.preferred_encryption_algo:
            req.encryption_algo_client_to_server.insert(
                0, self.preferred_encryption_algo
            )
            req.encryption_algo_server_to_client.insert(
                0, self.preferred_encryption_algo
            )
        if self.preferred_server_host_key_algo:
            req.server_host_key_algo.insert(0, self.preferred_server_host_key_algo)
        if self.preferred_mac_algo:
            req.mac_algo_client_to_server.insert(0, self.preferred_mac_algo)
            req.mac_algo_server_to_client.insert(0, self.preferred_mac_algo)

        await self.sock.send_packet(bytes(req))
        packet = await self.sock.read_packet()
        resp = HANDLERS[packet.opcode].parse(Buffer(packet.payload))
        self.server_kex_init = resp
        self.kex_init = req
        self.set_algos(resp)
        kex_result = await self.available_kex_algo[self.kex_algo](self).start()
        if not self.session_id:
            self.session_id = kex_result.H
        self.set_ciphers(kex_result.K, kex_result.H)
        await self.end_kex_init()
        self.sock.start_encryption()
        # await self.sock.send_packet(bytes(self.kex_init))

    def set_algos(self, server_kex: SSHMsgKexInit):
        self.kex_algo = list(
            filter(
                lambda x: x in server_kex.kex_algo,
                chain((self.preferred_kex_algo,), self.available_kex_algo),
            )
        )[0]
        self.server_host_key_algo = list(
            filter(
                lambda x: x in server_kex.server_host_key_algo,
                chain(
                    (self.preferred_server_host_key_algo,),
                    self.available_server_host_key_algo,
                ),
            )
        )[0]
        self.encryption_algo = list(
            filter(
                lambda x: x in server_kex.encryption_algo_client_to_server,
                chain(
                    (self.preferred_encryption_algo,), self.available_encryption_algo
                ),
            )
        )[0]
        self.mac_algo = list(
            filter(
                lambda x: x in server_kex.mac_algo_client_to_server,
                chain((self.preferred_mac_algo,), self.available_mac_algo),
            )
        )[0]
        self.compression_algo = "none"  # TODO
        self.logger.log(logging.DEBUG, "Kex Algo: %s", self.kex_algo)
        self.logger.log(
            logging.DEBUG, "server host key algo: %s", self.server_host_key_algo
        )
        self.logger.log(logging.DEBUG, "encryption algo: %s", self.encryption_algo)
        self.logger.log(logging.DEBUG, "mac algo: %s", self.mac_algo)
        self.logger.log(logging.DEBUG, "compression algo: %s", self.compression_algo)

    def set_ciphers(self, K, H):
        # K || H || "A" || session_id)
        # https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
        # Dont use any cipher or mac algo that needs key greater choosen sha
        b = util.deflate_long(K)
        K = int.to_bytes(len(b), 4) + b  # mpint encoded
        hash_algo = self.available_kex_algo[self.kex_algo].hash_algo
        encryptor = self.available_encryption_algo[self.encryption_algo]
        key_size, iv_size = encryptor.key_size, encryptor.block_size
        mac_algo = self.available_mac_algo[self.mac_algo]
        if mac_algo is None:
            pass
        else:
            mac_size = mac_algo.size
        client_to_server_iv = hash_algo(K + H + b"A" + self.session_id)[:iv_size]
        server_to_client_iv = hash_algo(K + H + b"B" + self.session_id)[:iv_size]
        client_to_server_key = hash_algo(K + H + b"C" + self.session_id)[:key_size]
        server_to_client_key = hash_algo(K + H + b"D" + self.session_id)[:key_size]
        if mac_algo is not None:
            client_to_server_mac = hash_algo(K + H + b"E" + self.session_id)[:mac_size]
            server_to_client_mac = hash_algo(K + H + b"F" + self.session_id)[:mac_size]
            self.sock.set_mac_algo(
                mac_algo(client_to_server_mac), mac_algo(server_to_client_mac)
            )

        self.sock.set_encryptor(
            encryptor(client_to_server_key, client_to_server_iv),
            encryptor(server_to_client_key, server_to_client_iv),
        )
        assert len(client_to_server_iv) == iv_size, (
            "(iv size) %s != cipher iv_size (%s)" % (len(client_to_server_iv), iv_size)
        )
        assert len(client_to_server_key) == key_size, (
            "(key size) %s != cipher key_size (%s)"
            % (len(client_to_server_key), key_size)
        )
        if mac_algo:
            assert len(client_to_server_mac) == mac_size, (
                "(mac key size) %s != mac key_size (%s)"
                % (len(client_to_server_mac), mac_size)
            )

    async def end_kex_init(self):
        req = SSHMsgNewKeys()
        await self.sock.send_packet(bytes(req))
        packet = await self.sock.read_packet()
        self.logger.log(DEBUG, "New keys: %s", packet.opcode)

    async def send_message(self, msg: SSHMessage):
        await self.sock.send_packet(bytes(msg))

    async def auth_password(self, username, password=""):
        svc = SSHMsgServiceRequest(service_name="ssh-userauth")
        await self.send_message(svc)
        self.logger.info("waiting for accept")
        if not await self.wait_for_message(SSHMsgServiceAccept, 5, silent=True):
            self.logger.info("service request timeout auth failed")
            return
        self.logger.info("accepted")
        auth = SSHMsgUserauthRequest(
            username=username,
            service_name="ssh-connection",
            method_name="password",
            password=password,
            flag=False,
        )
        await self.send_message(auth)
        await self.do_auth()
        # self.wait_for_message()

    async def auth_public_key(self, username, key_path=""):
        svc = SSHMsgServiceRequest(service_name="ssh-userauth")
        await self.send_message(svc)
        if not await self.wait_for_message(SSHMsgServiceAccept, 10, silent=True):
            self.logger.info("service request timeout auth failed")
            return
        pk = key.RSAKey.from_file(key_path)
        signature = self.compute_auth_signature(username, pk)
        signature = bytes(SSHSignature(algo=self.server_host_key_algo, sig=signature))

        auth = SSHMsgUserauthRequest(
            username=username,
            service_name="ssh-connection",
            method_name="publickey",
            flag=True,
            pub_key_algo=self.server_host_key_algo,
            pub_key=bytes(pk),
            signatrue=signature,
        )
        await self.send_message(auth)
        await self.do_auth()

    async def do_auth(self):
        self.auth_event.clear()
        await self.auth_event.wait()
        if not self.authenticated:
            if self.server_closed:
                raise TypeError("Authentication Failed %s"%self.close_reason)
            raise TypeError("Authencation error")
        return True


    def compute_auth_signature(self, username, pk):
        b = Buffer()
        b.write_binary(self.session_id)
        b.write_byte(int.to_bytes(SSHMsgUserauthRequest.opcode, 1))
        for x in (
            username,
            "ssh-connection",
            "publickey",
            True,
            self.server_host_key_algo,
            bytes(pk),
        ):
            if isinstance(x, bool):
                b.write_bool(x)
            elif isinstance(x, bytes):
                b.write_binary(x)
            else:
                b.write_string(x)
        return pk.sign(b.getvalue(), self.server_host_key_algo)

    def _log(self, level, message):
        self.logger.log(level, message)

    async def wait_for_message(self, msg: SSHMessage, timeout=120, silent=False):
        ev = curio.Event()
        self.events[msg.opcode] = ev
        self.logger.info("Waiting for message %s", msg)
        try:
            async with curio.timeout_after(timeout):
                await ev.wait()
        except curio.TaskTimeout:
            self.logger.info("Task timeout after %s" % timeout)
            if silent:
                return False
            raise
        self.logger.info("received signal done waiting %s", msg)
        return True

    async def open_session(self) -> Channel:
        chid = Channel.next_id()
        m = SSHMsgChannelOpen(
            type="session",
            sender_channel=chid,
            max_packet=32768 // 2,
            window_size=2 << 31 - 1,
        )
        return await self.do_open_channel(m)

    async def do_open_channel(self, msg):
        await self.send_message(msg)
        ev = curio.Event()
        self.channel_events[msg.sender_channel] = ev
        await ev.wait()
        ch = self.channels[msg.sender_channel]
        if isinstance(ch, ChannelError):
            self.channels.pop(msg.sender_channel)
            raise TypeError(ch.err)
        return ch

    async def run_command(self, cmd):
        ch = await self.open_session()
        ch.run_command(cmd)
        return ch

    async def open_port_forward(self, dest_addr, dest_port, src_addr, src_port):
        m = SSHMsgChannelOpen(
            type="direct-tcpip",
            sender_channel=Channel.next_id(),
            max_packet=32768 // 2,
            window_size=2 << 31 - 1,
            address=dest_addr,
            port=dest_port,
            src_address=src_addr,
            src_port=src_port,
        )
        return await self.do_open_channel(m)

    async def close(self):
        for task in self.tasks:
            await task.cancel()
        for task in self.tasks:
            try:
                await task.join()
            except Exception:
                pass
        await self.sock.close()

    async def clean_up_tasks(self):
        while True:
            for task in self.tasks:
                if task.terminated:
                    await task.join()
            await curio.sleep(5)
    
    ### handlers
    async def handle_auth_response(self,msg:SSHMsgUserauthSuccess):
        self.logger.info(msg)
        if isinstance(msg,SSHMsgUserauthFailure):
            self.authenticated = False
            self.logger.info("auth failure %s",msg)
        else:
            self.authenticated = True
        await self.auth_event.set()
            
    async def handle_message_disconnect(self, m: SSHMsgDisconnect):
        self.logger.log(logging.INFO, "Received disconnect message (%s)", m.description)
        for e in self.events.values():
            await e.set()
        self.close_reason = m.description
        self.server_closed = True
        await self.auth_event.set()
        await self.close()
        # raise RuntimeError("server closed clonnection: %s"%m.description)

    async def handle_channel_message(self, m: SSHMsgChannelEOF):
        chan_id = m.recipient_channel
        channel = self.channels.get(chan_id)
        if m.opcode == SSHMsgChannelClose.opcode:
            self.logger.log(INFO, "Channel closed (%s)", m.recipient_channel)
            channel.close()
            self.channels.pop(chan_id)
        if m.opcode == SSHMsgChannelSuccess.opcode:
            # channel requests succes
            self.logger.log(INFO, "Channel request success (%s)", m.recipient_channel)
        if m.opcode == SSHMsgChannelFailure.opcode:
            # channel request failure
            self.logger.log(INFO, "Channel request failure (%s)", m.recipient_channel)
        if m.opcode == SSHMsgChannelEOF.opcode:
            self.logger.log(INFO, "Channel eof (%s)", m.recipient_channel)
            await channel.set_eof()
        if m.opcode == SSHMsgChannelRequest.opcode:
            self.logger.info("exit code %s", chan_id)
            if m.type != "exit-status":
                self.logger.info("Unknow chnannel request type %s", m.type)
                return
            channel.set_exit_code(m.exit_status)

    async def handle_channel_data(self, m: SSHMsgChannelData):
        data = m.data
        chan_id = m.recipient_channel
        channel = self.channels.get(chan_id)
        if isinstance(m, SSHMsgChannelExtendData):
            self.logger.log(INFO, "Channel  data stderr (%s)", m.recipient_channel)
            print(data.decode())
            await channel.set_ext_data(data)
        else:
            self.logger.log(INFO, "Channel  data stdout (%s)", m.recipient_channel)
            await channel.set_data(data)

    async def handle_service_accept(self, svc: SSHMsgServiceAccept):
        self.auth.set_event()

    async def handle_channel_open(self, msg: SSHMsgChannelOpenConfirmation):
        chid = msg.recipient_channel
        ev = self.channel_events.pop(chid)
        if isinstance(msg, SSHMsgChannelOpenFailure):
            self.logger.info("channel open failed %s", msg.description)
            description = msg.error_map.get(msg.reason_code, msg.description)
            self.channels[chid] = ChannelError("channel open failed %s" % description)
        else:
            channel = Channel(self, chid, msg.sender_channel)
            self.channels[chid] = channel
            self.logger.info("Channel open success %s", chid)
        await ev.set()


    async def __aenter__(self):
        return self

    async def __aexit__(self,*args):
        await self.close()

    # def __await__(self):
    # rself.close_event.wait()
    # self.logger.info("existing")
