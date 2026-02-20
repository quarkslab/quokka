from enum import IntEnum
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import quokka


class EnumT(IntEnum):
    """Base class for all enums in quokka"""

    @staticmethod
    def from_proto(proto: "quokka.pb.Quokka.EnumType") -> "EnumT":
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
            enum_class.xrefs = xrefs
            enum_class.base_type = proto.base_type

        except ValueError as exc:
            raise ValueError(f"Invalid protobuf enum value {proto_enum} for {cls.__name__}") from exc
    
