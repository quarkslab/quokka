
from functools import cached_property
import weakref
from enum import IntEnum, auto, Enum, EnumMeta
from typing import TYPE_CHECKING, Iterable, Type

from quokka.quokka_pb2 import Quokka as Pb # pyright: ignore[reportMissingImports]
from quokka.types import AddressT, RefType, Index

if TYPE_CHECKING:
    from quokka import Program, Data
from abc import ABC, ABCMeta, abstractmethod


class CoreType(ABC):
    """Abstract base class for all types in quokka"""

    @property
    def is_member(self) -> bool:
        """Return True if this type is a member (StructureTypeMember or EnumTypeMember)"""
        return False

    @property
    def is_base_type(self) -> bool:
        """Return True if this type is a base type"""
        return isinstance(self, BaseType)

    @property
    def is_enum(self) -> bool:
        """Return True if this type is an enum"""
        return isinstance(self, EnumType)

    @property
    def is_struct(self) -> bool:
        """Return True if this type is a structure"""
        return isinstance(self, StructureType)

    @property
    def is_union(self) -> bool:
        """Return True if this type is a union"""
        return isinstance(self, UnionType)

    @property
    def is_array(self) -> bool:
        """Return True if this type is an array"""
        return isinstance(self, ArrayType)

    @property
    def is_pointer(self) -> bool:
        """Return True if this type is a pointer"""
        return isinstance(self, PointerType)

    @property
    def is_composite(self) -> bool:
        """Return True if this type is a composite type (struct, union, array, pointer)"""
        return isinstance(self, ComplexType)


class EnumABCMeta(EnumMeta, ABCMeta):
    """Combined metaclass for ABC + Enum compatibility"""
    pass


class BaseType(CoreType, IntEnum, metaclass=EnumABCMeta):
    """Data Type"""

    UNKNOWN = 0
    BYTE = 1
    WORD = 2
    DOUBLE_WORD = 3
    QUAD_WORD = 4
    OCTO_WORD = 5
    FLOAT = 6
    DOUBLE = 7
    VOID = 8

    @staticmethod
    def from_proto(data_type: Pb.BaseType) -> "BaseType":
        """Convert the protobuf value into this enumeration"""
        return BaseType(data_type)
    
    @property
    def size(self) -> int:
        """Size of the data type in bytes"""
        mapping = {
            BaseType.BYTE: 1,
            BaseType.WORD: 2,
            BaseType.DOUBLE_WORD: 4,
            BaseType.QUAD_WORD: 8,
            BaseType.OCTO_WORD: 16,
            BaseType.FLOAT: 4,
            BaseType.DOUBLE: 8,
            BaseType.VOID: 0,
        }

        return mapping.get(self, 0)

    def __str__(self) -> str:
        """String representation of the data type"""
        ts = {
            BaseType.UNKNOWN: "unknown",
            BaseType.BYTE: "char",
            BaseType.WORD: "short",
            BaseType.DOUBLE_WORD: "int",
            BaseType.QUAD_WORD: "int64_t",
            BaseType.OCTO_WORD: "int128_t",
            BaseType.FLOAT: "float",
            BaseType.DOUBLE: "double",
            BaseType.VOID: "void",
        }[self]
        return f"<T:{ts}>"

    @property
    def type_index(self) -> int:
        """Return the protobuf type index of this type"""
        return self.value

    @property
    def c_str(self) -> str:
        """Return the C declaration of this type"""
        return str(self)


class ComplexType(CoreType):
    def __init__(self, proto_index: Index, proto: Pb.CompositeType|Pb.EnumType, program: "Program"):
        self.type_index = proto_index
        self.proto = proto
        self._program = program

        self.name: str = proto.name
        # type is not used here
        self.size = proto.size if hasattr(proto, "size") else 0
        self.c_str = proto.c_str

        # Xrefs attached to the type itself
        self._xrefs_to = [self._program.proto.references[x] for x in proto.xref_to]
        self._xrefs_to = [(RefType(ref.reference_type), ref) for ref in self._xrefs_to]
    
    @property
    def comments(self) -> list[str]:
        """Return the type comments"""
        return self.proto.comments if hasattr(self.proto, "comments") else []

    @property
    def data_refs_to(self) -> list['Data']:
        """Returns all data reference to this type"""
        # Get protobuf type ids
        return [self._program.data_holder[xref.source.address] for t, xref in self._xrefs_to if t.is_data]

    @property
    def data_read_refs_to(self) -> list['Data']:
        """Returns all data read reference to this instruction"""
        return [self._program.data_holder[xref.source.address] for t, xref in self._xrefs_to if t in [RefType.DATA_READ, RefType.DATA_INDIR]]

    @property
    def data_write_refs_to(self) -> list['Data']:
        """Returns all data write reference to this instruction"""
        return [self._program.data_holder[xref.source.address] for t, xref in self._xrefs_to if t == RefType.DATA_WRITE]


class EnumTypeMember(CoreType):
    """EnumTypeMember

    This class represents enum members.

    Arguments:
        member: Protobuf data
        enum_type: Reference to the parent enum type

    Attributes:
        name: Member name
        size: Member size (if known)
        value: Member value
        comments: Member comments
    """

    def __init__(self, member: "Pb.EnumType.EnumValue", enum_type: "EnumType") -> None:
        """Constructor"""
        self.proto = member
        self.name: str = member.name
        self.value: int = member.value
        self.size: int = enum_type.size
        self._enum_type: weakref.ref[EnumType] = weakref.ref(enum_type)
        self._xrefs_to = [enum_type._program.proto.references[x] for x in member.xref_to]

    @property
    def base_type(self) -> BaseType:
        """Return the base type of the enum member"""
        return self._enum_type().base_type # type: ignore

    @property
    def comments(self) -> list[str]:
        """Return the enum member comments"""
        return self.proto.comments

    @property
    def parent(self) -> "EnumType":
        """Back reference to the parent enum"""
        return self._enum_type() # type: ignore

    @property
    def data_refs_to(self) -> list['Data']:
        """Returns all data reference to this type"""
        # Get protobuf type ids
        return [self.parent._program.data_holder[xref.source.address] for xref in self._xrefs_to 
                if RefType.from_proto(xref.reference_type).is_data]

    @property
    def is_member(self) -> bool:
        return True

    def __str__(self) -> str:
        return f"<TEnumTypeMember: {self.parent.name}.{self.name}>"


class EnumType(ComplexType):
    """Base class for all enums in quokka"""
    
    def __init__(self, index: Index, proto: Pb.EnumType, program: "Program") -> None:
        """Create an enum from a protobuf enum value"""
        super().__init__(index, proto, program)
        self.name = proto.name
        self._members: dict[str, EnumTypeMember] = {member.name: EnumTypeMember(member, self) 
                                                    for member in proto.values}
        self._members_by_idx = [self._members[x.name] for x in proto.values]
        self.size = self.base_type.size

    @property
    def base_type(self) -> BaseType:
        """Return the base type of the enum"""
        typ = self._program.get_type(self.proto.base_type)
        assert isinstance(typ, BaseType)
        return typ
    
    @property
    def members(self) -> Iterable[EnumTypeMember]:
        """Return the enum members as a mapping from member names to members"""
        return iter(self)

    def __iter__(self):
        """Iterate over the enum members"""
        return iter(self._members.values())

    def __getitem__(self, key: int) -> EnumTypeMember:
        return self._members_by_idx[key]

    def __getattr__(self, name):
        if name in self._members:
            return self._members[name]
        else:
            return super().__getattribute__(name)

    def __str__(self) -> str:
        return f"<TEnum: {self.name}>"

class ArrayType(ComplexType):
    """Array type

    Arguments:
        proto: Protobuf data
        program: Back reference to the program

    Attributes:
        name: Type name
        size: Type size (if known)
        c_str: C declaration of the type
    """
    def __init__(self, index: Index, proto: Pb.CompositeType, program: "Program") -> None:
        """Constructor"""
        super().__init__(index, proto, program)
    
    @property
    def array_size(self) -> int:
        """Return the number of items in the array"""
        return self.proto.size // self.element_type.size if self.element_type.size > 0 else 0

    @property
    def element_type(self) -> 'TypeT':
        """Return the type of the array elements"""
        return self._program.get_type(self.proto.element_type_idx)

    def __str__(self) -> str:
        return f"<TArray: {self.name} {self.element_type}[{self.size}]>"

class PointerType(ComplexType):
    """Pointer type

    Arguments:
        proto: Protobuf data
        program: Back reference to the program

    Attributes:
        name: Type name
        size: Type size (if known)
        c_str: C declaration of the type
    """
    def __init__(self, index: Index, proto: Pb.CompositeType, program: "Program") -> None:
        """Constructor"""
        super().__init__(index, proto, program)
    
    @property
    def pointed_type(self) -> 'TypeT':
        """Return the type of the pointed element"""
        return self._program.get_type(self.proto.element_type_idx)

    def __str__(self) -> str:
        return f"<TPtr: {self.name}->{self.pointed_type}*>"


class StructureTypeMember(CoreType):
    """StructureMember

    This class represents structure members (fields).

    Arguments:
        member: Protobuf data
        structure: Reference to the parent structure

    Attributes:
        name: Member name
        offset: Bit offset within the parent composite type
        size: Member size in bits (0 for variable-length members)
        type: Member data type
        comments: Member comments
    """

    def __init__(self, member: "Pb.CompositeType.Member", structure: "StructureType") -> None:
        """Constructor"""
        self.proto = member
        self.name: str = member.name
        self.offset: int = member.offset  # Bit offset within composite
        self.size: int = member.size  # Size in bits
        self._structure: weakref.ref[StructureType] = weakref.ref(structure)
        self._xrefs_to = [structure._program.proto.references[x] for x in member.xref_to]

    @property
    def comments(self) -> list[str]:
        """Return the structure member comments"""
        return self.proto.comments

    @property
    def type(self) -> 'TypeT':
        """Return the type of the member"""
        return self.parent._program.get_type(self.proto.type_index)

    @property
    def parent(self) -> "StructureType":
        """Back reference to the parent structure"""
        return self._structure() # type: ignore

    @property
    def data_refs_to(self) -> list['AddressT']:
        """Returns all data reference to this type.
        
        Addresses can originates from code or data."""
        # Get protobuf type ids
        return [xref.source.address for xref in self._xrefs_to 
                if RefType.from_proto(xref.reference_type).is_data]

    @property
    def is_member(self) -> bool:
        return True

    def __str__(self) -> str:
        t = "Struct" if self.parent.is_struct else "Union"
        return f"<T{t}Member: {self.parent.name}.{self.name}>"


class StructureType(dict, ComplexType):
    """Structure

    Members are stored in a dict keyed by **bit offset** and also in an ordered
    list (``_members_list``) for positional access.

    Arguments:
        structure: Structure protobuf data
        program: Program back reference

    Attributes:
        program: Program backreference
        name: Structure name
        size: Structure size (if known)
        type: Structure type
        comments: Structure comments
    """

    def __init__(self, index: Index, proto: "Pb.CompositeType", program: "Program") -> None:
        """Constructor"""
        dict.__init__(self)
        ComplexType.__init__(self, index, proto, program)

        self._members_list: list[StructureTypeMember] = []
        for member in proto.members:
            m = StructureTypeMember(member, self)
            self._members_list.append(m)
            self[m.offset] = m

    @cached_property
    def members(self) -> list[StructureTypeMember]:
        """Return all members in declaration order"""
        return list(self._members_list)

    def member_at(self, index: int) -> StructureTypeMember:
        """Return a member by positional index (declaration order)."""
        return self._members_list[index]

    def is_variable_size(self) -> bool:
        """Is the structure of variable size?"""
        return self.size <= 0

    def __str__(self) -> str:
        return f"<TStruct: {self.name}>"


class UnionType(StructureType):
    """Union

    This class represents a union. It is a special case of structure where all members are at the same offset.
    To avoid dict-key collisions the
    dict is keyed by **positional index** instead of offset.

    Arguments:
        structure: Structure protobuf data
        program: Program back reference
    """

    def __init__(self, index: Index, proto: "Pb.CompositeType", program: "Program") -> None:
        dict.__init__(self)
        ComplexType.__init__(self, index, proto, program)

        self._members_list: list[StructureTypeMember] = []
        self.index_to_offset: dict[int, int] = {}
        for index, member in enumerate(proto.members):
            m = StructureTypeMember(member, self)
            self._members_list.append(m)
            self[index] = m
            self.index_to_offset[index] = member.offset

    def __str__(self) -> str:
        return f"<TUnion: {self.name}>"


TypeT = StructureType | BaseType | UnionType | ArrayType | PointerType | EnumType
TypeReference = TypeT | StructureTypeMember | EnumTypeMember
TypeValue = int | float | str | bytes | EnumType  # and later we can add struct instances, arrays, etc.
