
import weakref
from enum import IntEnum, auto, Enum
from typing import TYPE_CHECKING, Type


from quokka.quokka_pb2 import Quokka as Pb # pyright: ignore[reportMissingImports]
from quokka.types import AddressT

if TYPE_CHECKING:
    from quokka import Program


class BaseType(Enum):
    """Data Type"""

    UNKNOWN = auto()
    BYTE = auto()
    WORD = auto()
    DOUBLE_WORD = auto()
    QUAD_WORD = auto()
    OCTO_WORD = auto()
    FLOAT = auto()
    DOUBLE = auto()
    ASCII = auto()
    STRUCT = auto()
    ALIGN = auto()
    POINTER = auto()

    @staticmethod
    def from_proto(data_type: Pb.DataType) -> "BaseType":
        """Convert the protobuf value into this enumeration"""
        mapping = {
            Pb.TYPE_B: BaseType.BYTE,
            Pb.TYPE_W: BaseType.WORD,
            Pb.TYPE_DW: BaseType.DOUBLE_WORD,
            Pb.TYPE_QW: BaseType.QUAD_WORD,
            Pb.TYPE_OW: BaseType.OCTO_WORD,
            Pb.TYPE_FLOAT: BaseType.FLOAT,
            Pb.TYPE_DOUBLE: BaseType.DOUBLE,
            Pb.TYPE_ASCII: BaseType.ASCII,
            Pb.TYPE_STRUCT: BaseType.STRUCT,
            Pb.TYPE_ALIGN: BaseType.ALIGN,
            Pb.TYPE_POINTER: BaseType.POINTER,
        }

        return mapping.get(data_type, BaseType.UNKNOWN)

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
        }

        return mapping.get(self, 0)


class ComplexType(object):
    def __init__(self, proto: Pb.CompositeType, program: "Program"):
        self.proto = proto
        self._program = program

        self.name: str = proto.name
        # type is not used here
        self.size = proto.size
        self.c_str = proto.c_str

        # Xrefs attached to the type itself
        self._xrefs_to = [self._program.proto.references[x] for x in proto.xref_from]
    
    @property
    def data_refs_to(self) -> list[AddressT]:
        """Returns all data reference to this type"""
        # Get protobuf type ids
        return [xref.source.address for xref in self._xrefs_to
                if xref.reference_type == Pb.Reference.REF_DATA]

    @property
    def code_refs_to(self) -> list[AddressT]:
        """Returns all code reference to this type"""
        # Get protobuf type ids
        return [xref.source.address for xref in self._xrefs_to
                if xref.reference_type == Pb.Reference.REF_CODE]


class EnumType(IntEnum):
    """Base class for all enums in quokka"""

    @staticmethod
    def from_proto(proto: Pb.EnumType) -> Type["EnumType"]:
        """Create an enum from a protobuf enum value"""
        try:
            enum_dict = {
                enum_value.name: enum_value.value
                for enum_value in proto.values
            }
            xrefs = {
                enum_value.value: list(enum_value.xrefs)
                for enum_value in proto.values
            }
            enum_class = IntEnum(proto.name, enum_dict)
            # We attach extra attributes to the generated class
            setattr(enum_class, "xrefs", xrefs)
            setattr(enum_class, "base_type", proto.base_type)
            return enum_class # type: ignore

        except ValueError as exc:
            raise ValueError(f"Invalid protobuf enum value for {proto.name}") from exc


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
    def __init__(self, proto: Pb.CompositeType, program: "Program") -> None:
        """Constructor"""
        super().__init__(proto, program)
    
    @property
    def element_type(self) -> BaseType | EnumType | ComplexType:
        """Return the type of the array elements"""
        return self._program.get_type(self.proto.element_type_idx)


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
    def __init__(self, proto: Pb.CompositeType, program: "Program") -> None:
        """Constructor"""
        super().__init__(proto, program)
    
    @property
    def pointed_type(self) -> BaseType | EnumType | ComplexType:
        """Return the type of the pointed element"""
        return self._program.get_type(self.proto.element_type_idx)


class StructureTypeMember(object):
    """StructureMember

    This class represents structure members (fields).

    Arguments:
        member: Protobuf data
        structure: Reference to the parent structure

    Attributes:
        name: Member name
        size: Member size (if known)
        type: Member data type
        value: Member value
        comments: Member comments
    """

    def __init__(self, member: "Pb.CompositeType.Member", structure: "StructureType") -> None:
        """Constructor"""
        self.proto = member
        self.name: str = member.name
        self.offset: int = member.offset
        self.size: int = member.size
        self._structure: weakref.ref[StructureType] = weakref.ref(structure)
        self._xrefs_to = [structure._program.proto.references[x] for x in member.xref_to]

        self.comments: list[str] = []

    @property
    def type(self) -> BaseType | EnumType | ComplexType:
        """Return the type of the member"""
        return self.parent._program.get_type(self.proto.type_idx)

    @property
    def parent(self) -> "StructureType":
        """Back reference to the parent structure"""
        return self._structure() # type: ignore

    @property
    def data_refs_to(self) -> list[AddressT]:
        """Returns all data reference to this type"""
        # Get protobuf type ids
        return [xref.source.address for xref in self._xrefs_to 
                if xref.reference_type == Pb.Reference.REF_DATA]

    @property
    def code_refs_to(self) -> list[AddressT]:
        """Returns all code reference to this type"""
        # Get protobuf type ids
        return [xref.source.address for xref in self._xrefs_to 
                if xref.reference_type == Pb.Reference.REF_CODE]


class StructureType(dict, ComplexType):
    """Structure

    Arguments:
        structure: Structure protobuf data
        program: Program back reference

    Attributes:
        program: Program backreference
        name: Structure name
        size: Structure size (if known)
        type: Structure type
        index_to_offset: Mapping from offsets to structure members
        comments: Structure comments
    """

    def __init__(self, proto: "Pb.CompositeType", program: "Program") -> None:
        """Constructor"""
        dict.__init__(self)
        ComplexType.__init__(self, proto, program)

        self.index_to_offset: dict[int, int] = {}
        for index, member in enumerate(proto.members):
            self[member.offset] = StructureTypeMember(member, self)
            self.index_to_offset[index] = member.offset

        self.comments: list[str] = []

    def is_variable_size(self) -> bool:
        """Is the structure of variable size?"""
        return self.size <= 0


class UnionType(StructureType):
    """Union

    This class represents a union. It is a special case of structure where all members are at the same offset.

     Arguments:
        structure: Structure protobuf data
        program: Program back reference
    """
    pass


TypeT = StructureType | BaseType | UnionType | ArrayType | PointerType | EnumType
TypeValue = int | float | str | bytes | EnumType
