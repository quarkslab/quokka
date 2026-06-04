from pathlib import Path

from grpc_tools import protoc


EXTENSION_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = EXTENSION_DIR / "bn_quokka"

# The shared schema lives at the repository root; a local proto/ directory is
# supported as a fallback for standalone copies of this extension.
PROTO_DIR_CANDIDATES = (
    EXTENSION_DIR.parent / "proto",
    EXTENSION_DIR / "proto",
)


def _find_proto_dir() -> Path:
    for proto_dir in PROTO_DIR_CANDIDATES:
        if (proto_dir / "quokka.proto").is_file():
            return proto_dir
    raise FileNotFoundError(
        "quokka.proto not found in: "
        + ", ".join(str(path) for path in PROTO_DIR_CANDIDATES)
    )


def main() -> None:
    proto_dir = _find_proto_dir()
    proto_file = proto_dir / "quokka.proto"

    print(f"Generating {OUTPUT_DIR / 'quokka_pb2.py'} from {proto_file}")
    exit_code = protoc.main(
        [
            "grpc_tools.protoc",
            f"--proto_path={proto_dir}",
            f"--python_out={OUTPUT_DIR}",
            str(proto_file),
        ]
    )
    if exit_code != 0:
        raise RuntimeError(f"protoc failed with exit code {exit_code}")


if __name__ == "__main__":
    main()
