"""Instruction and operand export from BinaryNinja disassembly tokens."""

from __future__ import annotations

from typing import Any

from binaryninja import InstructionTextTokenType  # type: ignore

from ..context import ExportContext
from ..quokka_pb2 import Quokka


def export_instruction(
    ctx: ExportContext,
    builder: Quokka,
    tokens: list[Any],
    size: int,
    is_thumb: bool,
) -> int:
    instruction_index = len(builder.instructions)
    instruction = builder.instructions.add()
    instruction.size = max(0, size)
    instruction.mnemonic_index = _intern_string(
        ctx.mnemonic_indices, builder.mnemonics, extract_mnemonic(tokens)
    )
    instruction.is_thumb = is_thumb

    operands = operand_token_groups(tokens)
    mnemonic = extract_mnemonic(tokens).lower()
    for operand_idx, operand_tokens in enumerate(operands):
        instruction.operand_index.append(
            _export_operand(ctx, builder, mnemonic, operand_idx, operand_tokens)
        )

    return instruction_index


def _export_operand(
    ctx: ExportContext,
    builder: Quokka,
    mnemonic: str,
    operand_idx: int,
    tokens: list[Any],
) -> int:
    operand_index = len(builder.operands)
    operand = builder.operands.add()
    operand_text = _operand_text(tokens)
    operand.operand_string_index = _intern_string(
        ctx.operand_string_indices, builder.operand_strings, operand_text
    )
    operand.access = infer_operand_access(mnemonic, operand_idx)

    if tokens_are_memory(tokens):
        operand.type = Quokka.Operand.OPERAND_MEMORY
        address = _first_resolved_address(ctx, tokens)
        if address is not None:
            operand.address = address
    elif _tokens_are_register(tokens):
        operand.type = Quokka.Operand.OPERAND_REGISTER
        register_name = next(
            (token.text for token in tokens if token.type == InstructionTextTokenType.RegisterToken),
            operand_text,
        )
        operand.register_index = str(
            _intern_string(ctx.register_indices, builder.register_table, register_name)
        )
    else:
        value = _last_token_value(tokens)
        if value is not None:
            operand.type = Quokka.Operand.OPERAND_IMMEDIATE
            operand.value = value
        else:
            operand.type = Quokka.Operand.OPERAND_OTHER
            operand.other = operand_text

    return operand_index


def _intern_string(indexes: dict[str, int], values: Any, value: str) -> int:
    existing = indexes.get(value)
    if existing is not None:
        return existing
    index = len(values)
    values.append(value)
    indexes[value] = index
    return index


def extract_mnemonic(tokens: list[Any]) -> str:
    for token in tokens:
        if token.type == InstructionTextTokenType.InstructionToken:
            return token.text
    for token in tokens:
        text = token.text.strip()
        if text:
            return text
    return ""


def operand_token_groups(tokens: list[Any]) -> list[list[Any]]:
    groups: list[list[Any]] = []
    current: list[Any] = []
    seen_mnemonic = False

    for token in tokens:
        if not seen_mnemonic:
            if token.type == InstructionTextTokenType.InstructionToken:
                seen_mnemonic = True
            continue

        if token.type == InstructionTextTokenType.OperandSeparatorToken:
            if _operand_text(current):
                groups.append(current)
            current = []
            continue

        if token.type == InstructionTextTokenType.TextToken and not token.text.strip():
            if current:
                current.append(token)
            continue

        current.append(token)

    if _operand_text(current):
        groups.append(current)

    return groups


def _operand_text(tokens: list[Any]) -> str:
    return "".join(token.text for token in tokens).strip()


def tokens_are_memory(tokens: list[Any]) -> bool:
    return any(
        token.type
        in (
            InstructionTextTokenType.BeginMemoryOperandToken,
            InstructionTextTokenType.EndMemoryOperandToken,
        )
        or token.text in ("[", "]")
        for token in tokens
    )


def _tokens_are_register(tokens: list[Any]) -> bool:
    meaningful = [token for token in tokens if token.text.strip()]
    return bool(meaningful) and all(
        token.type == InstructionTextTokenType.RegisterToken for token in meaningful
    )


def _first_resolved_address(ctx: ExportContext, tokens: list[Any]) -> int | None:
    for token in tokens:
        value = token_value(token)
        if value is not None and ctx.resolve_segment_index(value) >= 0:
            return value
    return None


def _last_token_value(tokens: list[Any]) -> int | None:
    for token in reversed(tokens):
        value = token_value(token)
        if value is not None:
            return value
    return None


def token_value(token: Any) -> int | None:
    if token.type not in (
        InstructionTextTokenType.IntegerToken,
        InstructionTextTokenType.PossibleAddressToken,
        InstructionTextTokenType.CodeRelativeAddressToken,
        InstructionTextTokenType.CodeSymbolToken,
        InstructionTextTokenType.DataSymbolToken,
        InstructionTextTokenType.ExternalSymbolToken,
        InstructionTextTokenType.ImportToken,
        InstructionTextTokenType.IndirectImportToken,
        InstructionTextTokenType.PossibleValueToken,
    ):
        return None
    value = getattr(token, "value", 0)
    if value is None:
        return None
    value = int(value)
    if value > 0x7FFFFFFFFFFFFFFF:
        value -= 1 << 64
    return value


def infer_operand_access(mnemonic: str, operand_idx: int) -> int:
    if operand_idx != 0:
        return 1
    if mnemonic in {"add", "sub", "xor", "or", "and", "adc", "sbb", "inc", "dec"}:
        return 3
    if mnemonic in {"mov", "lea", "pop", "xchg", "imul", "shl", "shr", "sar", "sal"}:
        return 2
    return 1


__all__ = [
    "export_instruction",
    "extract_mnemonic",
    "infer_operand_access",
    "operand_token_groups",
    "token_value",
    "tokens_are_memory",
]
