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


class SSHMsgUnimplemented(SSHMessage):
    # SSH_MSG_UNIMPLEMENTED
    opcode = 3

    @classmethod
    def _parse(cls, data):
        return cls()


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


class SSHMsgDebug(SSHMessage):
    # SSH_MSG_DEBUG
    opcode = 4

    @classmethod
    def _parse(cls, data):
        return cls()


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
    host_pub_key_cert: bytes
    f: int
    sig: bytes

    def __bytes__(self):
        m = Buffer()
        m.write_binary(self.host_pub_key_cert)
        m.write_mpint(self.f)
        m.write_binary(self.sig)
        return m.getvalue()

    @classmethod
    def parse(cls, m: Buffer):
        cls.validate(m)
        return cls(
            host_pub_key_cert=m.read_binary(), f=m.read_mpint(), sig=m.read_binary()
        )


class SSHKexECDHInit(SSHMessage):
    desc = "SSH_KEX_ECDH_INIT"
    opcode: int = 30  # TODO
    client_pub_key: bytes

    @classmethod
    def parse(cls, buf: Buffer):
        cls.validate(buf)
        return cls(client_pub_key=buf.read_binary())

    def __bytes__(self):
        buf = Buffer()
        buf.write_binary(self.client_pub_key)
        return buf.getvalue()

        return super().parse(buf)


@dataclass
class SSHKexECDHReply(SSHMessage):
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


class ECDHHashSig:
    client_version: str
    server_version: str
    client_kex_init: str
    server_kex_init: str
    host_key: str
    client_pub_key: str
    server_pub_key: str
    K: int

    def __bytes__(self):
        m = Buffer()
        m.write_string(self.client_version)
        m.write_string(self.server_version)
        m.write_string(self.client_kex_init)
        m.write_string(self.server_kex_init)
        m.write_string(self.host_key)
        m.write_mpint(self.client_pub_key)
        m.write_mpint(self.server_pub_key)
        m.write_mpint(self.K)
        return m.getvalue()


HANDLERS = {}


for cls in locals().copy().values():
    try:
        if issubclass(cls, SSHMessage):
            HANDLERS[cls.opcode] = cls
    except TypeError:
        pass
