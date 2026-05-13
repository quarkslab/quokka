from pathlib import Path

from grpc_tools import protoc


EXTENSION_DIR = Path(__file__).resolve().parent
PROTO_DIR = EXTENSION_DIR / "proto"
OUTPUT_DIR = EXTENSION_DIR / "bn_quokka"
PROTO_FILE = PROTO_DIR / "quokka.proto"


def main() -> None:
    if not PROTO_FILE.exists():
        raise FileNotFoundError(
            f"Proto file not found: {PROTO_FILE}. "
            "Ensure binaryninja_extension/proto/quokka.proto points to the shared schema."
        )

    exit_code = protoc.main(
        [
            "grpc_tools.protoc",
            f"--proto_path={PROTO_DIR}",
            f"--python_out={OUTPUT_DIR}",
            str(PROTO_FILE),
        ]
    )
    if exit_code != 0:
        raise RuntimeError(f"protoc failed with exit code {exit_code}")


if __name__ == "__main__":
    main()
