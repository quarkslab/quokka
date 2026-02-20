
import quokka.pb.Quokka
from quokka.types import AddressT


class ComplexType(object):
    def __init__(self, proto: "quokka.pb.Quokka.CompositeType", program: "Program"):
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
        return [xref.source.address for xref in self._xrefs_to if xref.reference_type == quokka.pb.Quokka.Reference.REF_DATA]

    @property
    def code_refs_to(self) -> list[AddressT]:
        """Returns all code reference to this type"""
        # Get protobuf type ids
        return [xref.source.address for xref in self._xrefs_to if xref.reference_type == quokka.pb.Quokka.Reference.REF_CODE]


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
    def __init__(self, proto: "quokka.pb.Quokka.CompositeType", program: "Program") -> None:
        """Constructor"""
        super().__init__(proto, program)
    
    @property
    def element_type(self) -> BaseType|ComplexType:
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
    def __init__(self, proto: "quokka.pb.Quokka.CompositeType", program: "Program") -> None:
        """Constructor"""
        super().__init__(proto, program)
    
    @property
    def pointed_type(self) -> BaseType|ComplexType:
        """Return the type of the pointed element"""
        return self._program.get_type(self.proto.element_type_idx)
