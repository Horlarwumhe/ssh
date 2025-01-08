from dataclasses import dataclass

from ssh.stream import Buffer


class SSHMessage:
    opcode = None

    @classmethod
    def validate(cls, m: Buffer):
        opcode = int.from_bytes(m.read_byte())
        assert opcode == cls.opcode, "Opcode mismatch cls.opcode != opcode %s != %s" % (
            cls.opcode,
            opcode,
        )

    @classmethod
    def parse(self, buf):
        return NotImplemented


@dataclass
class SSHMsgUserauthRequest(SSHMessage):
    # SSH_MSG_USERAUTH_REQUEST
    desc = "SSH_MSG_USERAUTH_REQUEST"
    opcode = 50
    username: str
    service_name: str
    method_name: str  # "publickey" "password" "hostbased
    flag: bool
    #   if method name is publickey
    pub_key_algo: str = b""
    pub_key: bytes = b""
    signatrue: bytes = b""  # if self.boolean is true
    ########################

    ##### password method_name
    password: bytes = b""

    def __bytes__(self):
        r = Buffer()
        r.write_byte(int.to_bytes(self.opcode, 1))
        r.write_string(self.username)
        r.write_string(self.service_name)
        r.write_string(self.method_name)
        r.write_bool(self.flag)
        if self.method_name == "password":
            r.write_string(self.password)
        elif self.method_name == "publickey":
            r.write_string(self.pub_key_algo)
            r.write_binary(self.pub_key)
            if self.flag:
                r.write_binary(self.signatrue)
        return r.getvalue()


@dataclass
class SSHMsgUserauthFailure(SSHMessage):
    # SSH_MSG_USERAUTH_FAILURE
    desc = "SSH_MSG_USERAUTH_FAILURE"
    opcode = 51
    methods: list[str]
    partial: bool

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        return cls(methods=buf.read_list(), partial=buf.read_bool())


@dataclass
class SSHMsgUserauthSuccess(SSHMessage):
    # SSH_MSG_USERAUTH_SUCCESS
    desc = "SSH_MSG_USERAUTH_SUCCESS"
    opcode = 52

    @classmethod
    def parse(cls, buf):
        cls.validate(buf)
        return cls()


class SSHMsgUserauthBanner(SSHMessage):
    # SSH_MSG_USERAUTH_BANNER
    opcode = 53

    @classmethod
    def _parse(cls, data):
        return cls()


class SSHMsgUserauthPkOk(SSHMessage):
    # SSH_MSG_USERAUTH_PK_OK
    opcode = 60

    @classmethod
    def _parse(cls, data):
        return cls()


class SSHMsgUserauthPasswdChangereq(SSHMessage):
    # SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
    opcode = 60

    @classmethod
    def _parse(cls, data):
        return cls()


@dataclass
class SSHMsgDisconnect(SSHMessage):
    desc = "SSH_MSG_DISCONNECT"
    opcode = 1
    reason_code: int
    description: str
    lang: str

    @classmethod
    def parse(cls, m: Buffer):
        cls.validate(m)
        return cls(
            reason_code=m.read_int(),
            description=m.read_string(),
            lang=m.read_string(),
        )

    def __bytes__(self):
        w = Buffer()
        w.write_int(self.reason_code)
        w.write_string(self.description)
        w.write_string(self.lang)
        return bytes(w)


class SSHMsgIgnore(SSHMessage):
    # SSH_MSG_IGNORE
    opcode = 2

    @classmethod
    def _parse(cls, data):
        return cls()


@dataclass
class SSHMsgUnimplemented(SSHMessage):
    # SSH_MSG_UNIMPLEMENTED
    opcode = 3
    number: int

    @classmethod
    def parse(cls, data: Buffer):
        cls.validate(data)
        return cls(number=data.read_int())


@dataclass
class SSHMsgKexInit(SSHMessage):
    desc = "SSH_MSG_KEX_INIT"
    opcode = 20
    cookie: bytes
    kex_algo: list[str]
    server_host_key_algo: list[str]
    encryption_algo_client_to_server: list[str]
    encryption_algo_server_to_client: list[str]
    mac_algo_client_to_server: list[str]
    mac_algo_server_to_client: list[str]
    compression_algo_client_to_server: list[str]
    compression_algo_server_to_client: list[str]
    languages_client_to_server: list[str]
    languages_server_to_client: list[str]
    first_kex_packet_follows: bool

    def __bytes__(self):
        m = Buffer()
        m.write_byte(int.to_bytes(self.opcode, 1))
        m.write_byte(self.cookie)
        m.write_list(self.kex_algo)
        m.write_list(self.server_host_key_algo)
        m.write_list(self.encryption_algo_client_to_server)
        m.write_list(self.encryption_algo_server_to_client)
        m.write_list(self.mac_algo_client_to_server)
        m.write_list(self.mac_algo_server_to_client)
        m.write_list(self.compression_algo_client_to_server)
        m.write_list(self.compression_algo_server_to_client)
        m.write_list(self.languages_client_to_server)
        m.write_list(self.languages_server_to_client)
        m.write_bool(self.first_kex_packet_follows)
        m.write_int(0)
        return m.getvalue()

    @classmethod
    def parse(cls, m: Buffer):
        cls.validate(m)
        kls = cls(
            cookie=m.read_byte(16),
            kex_algo=m.read_list(),
            server_host_key_algo=m.read_list(),
            encryption_algo_client_to_server=m.read_list(),
            encryption_algo_server_to_client=m.read_list(),
            mac_algo_client_to_server=m.read_list(),
            mac_algo_server_to_client=m.read_list(),
            compression_algo_client_to_server=m.read_list(),
            compression_algo_server_to_client=m.read_list(),
            languages_client_to_server=m.read_list(),
            languages_server_to_client=m.read_list(),
            first_kex_packet_follows=m.read_bool(),
        )
        m.read_int()  # unused
        return kls


@dataclass
class SSHMsgDebug(SSHMessage):
    # SSH_MSG_DEBUG
    desc = "SSH_MSG_DEBUG"
    opcode = 4
    display: bool
    message: str
    lang: str

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        return cls(
            display=buf.read_bool(), message=buf.read_string(), lang=buf.read_string()
        )


@dataclass
class SSHMsgServiceRequest(SSHMessage):
    desc = "SSH_MSG_SERVICE_REQUEST"
    opcode = 5
    service_name: str

    @classmethod
    def parse(cls, m: Buffer):
        cls.validate(m)
        return cls(service_name=m.read_string())

    def __bytes__(self):
        w = Buffer()
        w.write_byte(int.to_bytes(self.opcode, 1))
        w.write_string(self.service_name)
        return w.getvalue()


#
class SSHMsgServiceAccept(SSHMsgServiceRequest):
    desc = "SSH_MSG_SERVICE_ACCEPT"
    # similar to SSH_MSG_SERVICE_REQUEST
    opcode = 6


@dataclass
class SSHMsgKexDHInit(SSHMessage):
    desc = "SSH_MSG_KEXDH_INIT"
    opcode = 30
    e: int

    def __bytes__(self):
        m = Buffer()
        m.write_byte(int.to_bytes(self.opcode))
        m.write_mpint(self.e)
        return m.getvalue()

    @classmethod
    def parse(cls, m: Buffer):
        cls.validate(m)
        return cls(e=m.read_mpint())


@dataclass
class SSHMessageKexDHReply(SSHMessage):
    desc = " SSH_MSG_KEX_DH_REPLY"
    opcode = 31
    host_key: bytes
    f: int
    sig: bytes

    def __bytes__(self):
        m = Buffer()
        m.write_binary(self.host_key)
        m.write_mpint(self.f)
        m.write_binary(self.sig)
        return m.getvalue()

    @classmethod
    def parse(cls, m: Buffer):
        cls.validate(m)
        return cls(host_key=m.read_binary(), f=m.read_mpint(), sig=m.read_binary())


@dataclass
class SSHMsgKexECDHInit(SSHMessage):
    desc = "SSH_KEX_ECDH_INIT"
    opcode = 30  # TODO
    pub_key: bytes

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        return cls(pub_key=buf.read_binary())

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_binary(self.pub_key)
        return buf.getvalue()


@dataclass
class SSHMsgKexECDHReply(SSHMessage):
    desc = "SSH_KEX_ECDH_REPLY"
    opcode = 31  # CHANGE
    host_key: bytes
    pub_key: bytes
    sig: bytes

    @classmethod
    def parse(cls, buf):
        cls.validate(buf)
        return cls(
            host_key=buf.read_binary(), pub_key=buf.read_binary(), sig=buf.read_binary()
        )

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_binary(self.host_key)
        buf.write_binary(self.pub_key)
        buf.write_binary(self.sig)
        return buf.getvalue()


@dataclass
class SSHMsgNewKeys(SSHMessage):
    desc = "SSH_MSG_NEW_KEYS"
    opcode = 21

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.opcode, 1))
        return b.getvalue()

    @classmethod
    def parse(cls, buf):
        cls.validate(buf)
        return cls()
        # return super().parse(buf)


@dataclass
class SSHMsgChannelOpen(SSHMessage):
    desc = "SSH_MSG_CHANNEL_OPEN"
    opcode = 90
    type: str
    sender_channel: int
    window_size: int
    max_packet: int
    #  X-11 channel https://datatracker.ietf.org/doc/html/rfc4254#section-6.3.2
    address: str = ""
    port: int = 0
    # forwarded-tcpip/direct-tcpip https://datatracker.ietf.org/doc/html/rfc4254#section-7.2
    address: str = ""
    port: int = 0
    src_address: str = ""
    src_port: int = 0

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_string(self.type)
        buf.write_int(self.sender_channel)
        buf.write_int(self.window_size)
        buf.write_int(self.max_packet)

        if self.type == "x11":
            buf.write_string(self.address)
            buf.write_int(self.port)
        elif self.type in ("forwarded-tcpip", "direct-tcpip"):
            buf.write_string(self.address)
            buf.write_int(self.port)
            buf.write_string(self.src_address)
            buf.write_int(self.src_port)
        return buf.getvalue()

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        type_ = buf.read_string()
        sender_channel = buf.read_int()
        window_size = buf.read_int()
        max_packet = buf.read_int()
        if type_ == "x11":
            address = buf.read_string()
            port = buf.read_int()
            return cls(
                type=type_,
                sender_channel=sender_channel,
                window_size=window_size,
                max_packet=max_packet,
                address=address,
                port=port,
            )
        if type_ in ("forwarded-tcpip", "direct-tcpip"):
            address = buf.read_string()
            port = buf.read_int()
            src_address = buf.read_string()
            src_port = buf.read_int()
            return cls(
                type=type_,
                sender_channel=sender_channel,
                window_size=window_size,
                max_packet=max_packet,
                address=address,
                port=port,
                src_address=src_address,
                src_port=src_port,
            )
        return cls(
            type=type_,
            sender_channel=sender_channel,
            window_size=window_size,
            max_packet=max_packet,
        )


@dataclass
class SSHMsgChannelOpenConfirmation(SSHMessage):
    desc = "SSH_MSG_CHANNEL_OPEN_CONFIRMATION"
    opcode = 91
    recipient_channel: int
    sender_channel: int
    window_size: int
    max_packet: int

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        return cls(
            recipient_channel=buf.read_int(),
            sender_channel=buf.read_int(),
            window_size=buf.read_int(),
            max_packet=buf.read_int(),
        )

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_int(self.recipient_channel)
        buf.write_int(self.sender_channel)
        buf.write_int(self.window_size)
        buf.write_int(self.max_packet)
        return buf.getvalue()


@dataclass
class SSHMsgChannelOpenFailure(SSHMessage):
    # SSH_MSG_CHANNEL_OPEN_FAILURE
    opcode = 92
    error_map = {
        1: "SSH_OPEN_ADMINISTRATIVELY_PROHIBITED",
        2: "SSH_OPEN_CONNECT_FAILED",
        3: "SSH_OPEN_UNKNOWN_CHANNEL_TYPE",
        4: "SSH_OPEN_RESOURCE_SHORTAGE",
    }
    recipient_channel: int
    reason_code: int
    description: str
    lang: str

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        return cls(
            recipient_channel=buf.read_int(),
            reason_code=buf.read_int(),
            description=buf.read_string(),
            lang=buf.read_string(),
        )

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_int(self.recipient_channel)
        buf.write_int(self.reason_code)
        buf.write_string(self.description)
        buf.write_string(self.lang)
        return buf.getvalue()


@dataclass
class SSHMsgChannelData(SSHMessage):
    desc = "SSH_MSG_CHANNEL_DATA"
    opcode = 94
    recipient_channel: int
    data: bytes

    @classmethod
    def parse(cls, buf):
        cls.validate(buf)
        return cls(recipient_channel=buf.read_int(), data=buf.read_binary())

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_int(self.recipient_channel)
        buf.write_binary(self.data)
        return buf.getvalue()


@dataclass
class SSHMsgChannelExtendData(SSHMessage):
    desc = "SSH_MSG_CHANNEL_EXTENDED_DATA"
    opcode = 95
    recipient_channel: int
    code: int
    data: bytes

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        return cls(
            recipient_channel=buf.read_int(),
            code=buf.read_int(),
            data=buf.read_binary(),
        )

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_int(self.recipient_channel)
        buf.write_int(self.code)
        buf.write_binary(self.data)
        return buf.getvalue()


@dataclass
class SSHMsgWindowAdjust(SSHMessage):
    opcode = 93
    desc = "SSH_MSG_CHANNEL_WINDOW_ADJUST"
    recipient_channel: int
    size: int

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        return cls(recipient_channel=buf.read_int(), size=buf.read_int())

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_int(self.recipient_channel)
        buf.write_int(self.size)
        return buf.getvalue()


@dataclass
class SSHMsgChannelEOF(SSHMessage):
    desc = "SSH_MSG_CHANNEL_EOF"
    opcode = 96
    recipient_channel: int

    @classmethod
    def parse(cls, buf):
        cls.validate(buf)
        return cls(recipient_channel=buf.read_int())

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_int(self.recipient_channel)
        return buf.getvalue()


@dataclass
class SSHMsgChannelClose(SSHMsgChannelEOF):
    desc = "SSH_MSG_CHANNEL_CLOSE"
    opcode = 97


@dataclass
class SSHMsgChannelSuccess(SSHMsgChannelEOF):
    desc = "SSH_MSG_CHANNEL_SUCCESS"
    opcode = 99


@dataclass
class SSHMsgChannelFailure(SSHMsgChannelEOF):
    desc = "SSH_MSG_CHANNEL_FAILURE"
    opcode = 100


@dataclass
class SSHMsgChannelRequest(SSHMessage):
    desc = "SSH_MSG_CHANNEL_REQUEST"
    opcode = 98
    recipient_channel: int
    type: str
    want_reply: bool
    ##### pty-req request https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
    term_env_var: str = ""
    width_char: int = 0
    heigth_char: int = 0
    width_pixel: int = 0
    heigth_pixel: int = 0
    mode: str = ""
    #### X-11 request https://datatracker.ietf.org/doc/html/rfc4254#section-6.4
    single_conn: bool = True
    auth_protocoal: str = ""
    auth_cookie: bytes = b""
    screen_number: int = 0
    # env request  https://datatracker.ietf.org/doc/html/rfc4254#section-6.4
    name: str = ""
    value: str = ""
    # shell request
    # no data
    # subsystem request
    subsystem_name: str = ""
    # exec request
    command: str = ""
    # signal request
    signal_name: str = ""
    # exi-status request
    exit_status: int = 0
    # exit-signal
    signal_name: str = ""
    core_dump: bool = False
    error: str = ''
    lang: str = ""

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        recipient_channel = buf.read_int()
        type_ = buf.read_string()
        want_reply = buf.read_bool()
        if type_ == "pty-req":
            return cls(
                recipient_channel=recipient_channel,
                type=type_,
                want_reply=want_reply,
                term_env_var=buf.read_string(),
                width_char=buf.read_int(),
                heigth_char=buf.read_int(),
                width_pixel=buf.read_int(),
                heigth_pixel=buf.read_int(),
                mode=buf.read_string(),
            )
        elif type_ == "x11-req":
            return cls(
                recipient_channel=recipient_channel,
                type=type_,
                want_reply=want_reply,
                single_conn=buf.read_bool(),
                auth_protocoal=buf.read_string(),
                auth_cookie=buf.read_binary(),
                screen_number=buf.read_int(),
            )
        elif type_ == "env":
            return cls(
                recipient_channel=recipient_channel,
                type=type_,
                want_reply=want_reply,
                name=buf.read_string(),
                value=buf.read_string(),
            )
        elif type_ == "subsystem":
            return cls(
                recipient_channel=recipient_channel,
                type=type_,
                want_reply=want_reply,
                subsytem_name=buf.read_string(),
            )
        elif type_ == "exec":
            return cls(
                recipient_channel=recipient_channel,
                type=type_,
                want_reply=want_reply,
                command=buf.read_string(),
            )
        elif type_ == "signal":
            return cls(
                recipient_channel=recipient_channel,
                type=type_,
                want_reply=want_reply,
                signal_name=buf.read_string(),
            )
        elif type_ == "exit-status":
            return cls(
                recipient_channel=recipient_channel,
                type=type_,
                want_reply=want_reply,
                exit_status=buf.read_int(),
            )
        elif type_ == "exit-signal":
            return cls(
                recipient_channel=recipient_channel,
                type=type_,
                want_reply=want_reply,
                signal_name=buf.read_string(),
                core_dump=buf.read_bool(),
                error=buf.read_string(),
                lang=buf.read_string(),
            )
        else:
            # self.type == "shell"
            return cls(
                recipient_channel=recipient_channel,
                type=type_,
                want_reply=want_reply,
            )

    def __bytes__(self):
        buf = Buffer()
        buf.write_byte(int.to_bytes(self.opcode, 1))
        buf.write_int(self.recipient_channel)
        buf.write_string(self.type)
        buf.write_bool(self.want_reply)

        if self.type == "pty-req":
            buf.write_string(self.term_env_var)
            buf.write_int(self.width_char)
            buf.write_int(self.heigth_char)
            buf.write_int(self.width_pixel)
            buf.write_int(self.heigth_pixel)
            buf.write_string(self.mode)
        elif self.type == "x11-req":
            buf.write_bool(self.single_conn)
            buf.write_string(self.auth_protocoal)
            buf.write_binary(self.auth_cookie)
            buf.write_int(self.screen_number)
        elif self.type == "env":
            buf.write_string(self.name)
            buf.write_string(self.value)
        elif self.type == "subsystem":
            buf.write_string(self.subsystem_name)
        elif self.type == "exec":
            buf.write_string(self.command)
        elif self.type == "signal":
            buf.write_string(self.signal_name)
        elif self.type == "exit-status":
            buf.write_int(self.exit_status)

        return buf.getvalue()


@dataclass
class SSHMsgGlobalRequest(SSHMessage):
    desc = "SSH_MSG_GLOBAL_REQUEST"
    opcode = 80
    type: str
    want_reply: bool

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        # print(buf.getvalue())
        return cls(type=buf.read_string(), want_reply=buf.read_bool())


@dataclass
class DHHashSig:
    # H
    client_version: str
    server_version: str
    client_kex_init: bytes
    server_kex_init: bytes
    host_key: bytes
    e: int
    f: int
    K: int

    def __bytes__(self):
        m = Buffer()
        m.write_string(self.client_version)
        m.write_string(self.server_version)
        m.write_binary(self.client_kex_init)
        m.write_binary(self.server_kex_init)
        m.write_binary(self.host_key)
        m.write_mpint(self.e)
        m.write_mpint(self.f)
        m.write_mpint(self.K)
        return m.getvalue()


@dataclass
class ECDHHashSig:
    client_version: str
    server_version: str
    client_kex_init: str
    server_kex_init: str
    server_host_key: str
    client_pub_key: str
    server_pub_key: str
    K: int

    def __bytes__(self):
        m = Buffer()
        m.write_string(self.client_version)
        m.write_string(self.server_version)
        m.write_binary(self.client_kex_init)
        m.write_binary(self.server_kex_init)
        m.write_binary(self.server_host_key)
        m.write_binary(self.client_pub_key)
        m.write_binary(self.server_pub_key)
        m.write_mpint(self.K)
        return m.getvalue()


@dataclass
class SSHSignature:
    algo: str
    sig: bytes

    @classmethod
    def parse(cls, buf: Buffer):
        return cls(algo=buf.read_string(), sig=buf.read_binary())

    def __bytes__(self):
        buf = Buffer()
        buf.write_string(self.algo)
        buf.write_binary(self.sig)
        return buf.getvalue()


HANDLERS = {}


for cls in locals().copy().values():
    try:
        if issubclass(cls, SSHMessage):
            HANDLERS[cls.opcode] = cls
    except TypeError:
        pass
