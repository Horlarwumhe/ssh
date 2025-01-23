from dataclasses import dataclass

from ssh.stream import Buffer

int64 = int
ATTRS = object


class SFTPMessage:
    
    def __bytes__(self):
        return NotImplemented
    @classmethod
    def parse(cls,b:Buffer) -> "SFTPMessage":
        return NotImplemented


@dataclass
class SFTPAttributes:
    flags: int = 0
    size: int64 = None
    uid: int = None
    gid: int = None
    permissions: int = None
    atime: int = None
    mtime: int = None
    extended_count: int = None
    extended: dict = None

    @classmethod
    def parse(cls, b: Buffer):
        flags = b.read_int()
        size = b.read_int64() if flags & SSH_FILEXFER_ATTRS.SIZE else None
        uid = b.read_int() if flags & SSH_FILEXFER_ATTRS.UIDGID else None
        gid = b.read_int() if flags & SSH_FILEXFER_ATTRS.UIDGID else None
        permissions = b.read_int() if flags & SSH_FILEXFER_ATTRS.PERMISSIONS else None
        atime = b.read_int() if flags & SSH_FILEXFER_ATTRS.ACMODTIME else None
        mtime = b.read_int() if flags & SSH_FILEXFER_ATTRS.ACMODTIME else None
        extended = None
        if flags & SSH_FILEXFER_ATTRS.EXTENDED:
            extended = {}
            extended_count = b.read_int()
            for _ in range(extended_count):
                extended[b.read_string()] = b.read_string()
        return cls(
            flags=flags,
            size=size,
            uid=uid,
            gid=gid,
            permissions=permissions,
            atime=atime,
            mtime=mtime,
            extended=extended,
        )

    def __bytes__(self):
        flags = 0
        b = Buffer()
        if self.size is not None:
            flags |= SSH_FILEXFER_ATTRS.SIZE
            b.write_int64(self.size)
        if self.uid is not None and self.gid is not None:
            flags |= SSH_FILEXFER_ATTRS.UIDGID
            b.write_int(self.uid)
            b.write_int(self.gid)
        if self.permissions is not None:
            flags |= SSH_FILEXFER_ATTRS.PERMISSIONS
            b.write_int(self.permissions)
        if self.atime is not None and self.mtime is not None:
            flags |= SSH_FILEXFER_ATTRS.ACMODTIME
            b.write_int(self.atime)
            b.write_int(self.mtime)
        if self.extended is not None:
            flags |= SSH_FILEXFER_ATTRS.EXTENDED
            b.write_int(len(self.extended))
            for k, v in self.extended.items():
                b.write_string(k)
                b.write_string(v)
        return int.to_bytes(flags, 4, "big") + b.getvalue()


class SSH_FXF:
    READ = 0x00000001
    WRITE = 0x00000002
    APPEND = 0x00000004
    CREAT = 0x00000008
    TRUNC = 0x00000010
    EXCL = 0x00000020


class SSH_FILEXFER_ATTRS:
    SIZE = 0x00000001
    UIDGID = 0x00000002
    PERMISSIONS = 0x00000004
    ACMODTIME = 0x00000008
    EXTENDED = 0x80000000


class SSH_FXF_STATUS:
    OK = 0
    EOF = 1
    NO_SUCH_FILE = 2
    PERMISSION_DENIED = 3
    FAILURE = 4
    BAD_MESSAGE = 5
    NO_CONNECTION = 6
    CONNECTION_LOST = 7
    OP_UNSUPPORTED = 8


@dataclass
class SSHFXPINIT:
    code = 1
    version: int
    extensions: dict

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.version)
        return b.getvalue()


@dataclass
class SSHFXPVERSION:
    code = 2
    version: int
    extensions: dict

    @classmethod
    def parse(cls, b: Buffer):
        b.read_byte()
        version = b.read_int()
        extensions = {}
        while True:
            name = b.read_string()
            data = b.read_string()
            if not name:
                break
            extensions[name] = data
        return cls(version=version, extensions=extensions)


@dataclass
class SSHFXPOPEN:
    code = 3
    id: int
    filename: str
    pflags: int
    attrs: ATTRS

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_string(self.filename)
        b.write_int(self.pflags)
        b.write_byte(bytes(self.attrs))
        return b.getvalue()


@dataclass
class SSHFXPCLOSE:
    code = 4
    id: int
    handle: bytes

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_binary(self.handle)
        return b.getvalue()


@dataclass
class SSHFXPREAD:
    code = 5
    id: int
    handle: bytes
    offset: int64
    length: int

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_binary(self.handle)
        b.write_int64(self.offset)
        b.write_int(self.length)
        return b.getvalue()


@dataclass
class SSHFXPWRITE:
    code = 6
    id: int
    handle: str
    offset: int64
    data: bytes

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_binary(self.handle)
        b.write_int64(self.offset)
        b.write_binary(self.data)
        return b.getvalue()


@dataclass
class SSHFXPFSTAT:
    code = 8
    id: int
    handle: bytes

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_binary(self.handle)
        return b.getvalue()


@dataclass
class SSHFXPSETSTAT:
    code = 9
    id: int
    path: str
    attrs: dict

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_string(self.path)
        b.write_byte(bytes(self.attrs))
        return b.getvalue()


@dataclass
class SSHFXPOPENDIR:
    code = 11
    id: int
    path: str

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_string(self.path)
        return b.getvalue()


@dataclass
class SSHFXPREADDIR:
    code = 12
    id: int
    handle: bytes

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_binary(self.handle)
        return b.getvalue()


@dataclass
class SSHFXPREMOVE:
    code = 13
    id: int
    filename: str

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_string(self.filename)
        return b.getvalue()


@dataclass
class SSHFXPMKDIR:
    code = 14
    id: int
    path: str
    attrs: ATTRS

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_string(self.path)
        b.write_byte(bytes(self.attrs))
        return b.getvalue()


@dataclass
class SSHFXPRMDIR:
    code = 15
    id: int
    path: str

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_string(self.path)
        return b.getvalue()


@dataclass
class SSHFXPSTAT:
    code = 17
    id: int
    path: str

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_string(self.path)
        return b.getvalue()


@dataclass
class SSHFXPRENAME:
    code = 18
    id: int
    oldpath: str
    newpath: str

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_string(self.oldpath)
        b.write_string(self.newpath)
        return b.getvalue()


@dataclass
class SSHFXPSTATUS:
    code = 101
    id: int
    error: int
    message: str
    language_tag: str

    @classmethod
    def parse(cls, b: Buffer):
        b.read_byte()
        return cls(
            id=b.read_int(),
            error=b.read_int(),
            message=b.read_string(),
            language_tag=b.read_string(),
        )

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_int(self.error)
        b.write_string(self.message)
        b.write_string(self.language_tag)
        return b.getvalue()


@dataclass
class SSHFXPHANDLE:
    code = 102
    id: int
    handle: bytes

    @classmethod
    def parse(cls, b: Buffer):
        b.read_byte()
        return cls(id=b.read_int(), handle=b.read_binary())

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_string(self.handle)
        return b.getvalue()


@dataclass
class SSHFXPDATA:
    code = 103
    id: int
    data: bytes

    @classmethod
    def parse(cls, b: Buffer):
        b.read_byte()
        return cls(id=b.read_int(), data=b.read_binary())

    def __bytes__(self):
        b = Buffer()
        b.write_byte(int.to_bytes(self.code, 1))
        b.write_int(self.id)
        b.write_binary(self.data)
        return b.getvalue()


@dataclass
class SSHFXPNAME:
    code = 104
    id: int
    names: list[dict]

    @classmethod
    def parse(cls, b: Buffer):
        b.read_byte()
        id = b.read_int()
        names = []
        count = b.read_int()
        for _ in range(count):
            filename = b.read_string()
            longname = b.read_string()
            attrs = SFTPAttributes.parse(b)
            names.append({"filename": filename, "longname": longname, "attrs": attrs})
        return cls(id=id, names=names)


@dataclass
class SSHFXPATTRS:
    code = 105
    id: int
    attrs: SFTPAttributes

    @classmethod
    def parse(cls, b: Buffer):
        b.read_byte()
        id = b.read_int()
        attrs = SFTPAttributes.parse(b)
        return cls(id=id, attrs=attrs)


HANDLERS = {}
for name, cls in locals().copy().items():
    if name.startswith("SSHFXP"):
        HANDLERS[cls.code] = cls
