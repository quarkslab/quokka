"""Recipe to build automatically the doc for Python API reference

Derived from: https://mkdocstrings.github.io/recipes/
"""

from pathlib import Path

import mkdocs_gen_files

nav: mkdocs_gen_files.Nav = mkdocs_gen_files.Nav()

python_root: Path = Path("bindings/python").absolute()
full_doc: Path = Path("docs/reference/python").absolute()
full_doc.mkdir(exist_ok=True)

for path in python_root.rglob("*.py"):
    module_path = path.relative_to(python_root).with_suffix("")
    doc_path = path.relative_to(python_root / "quokka").with_suffix(".md")
    full_doc_path = full_doc / doc_path

    parts = list(module_path.parts)
    if parts[-1] in ("__init__", "__main__", "quokka_pb2"):
        continue

    nav[parts[1:]] = doc_path.as_posix()

    with mkdocs_gen_files.open(full_doc_path, "w") as fd:
        identifier = ".".join(parts)
        print("::: " + identifier, file=fd)

    mkdocs_gen_files.set_edit_path(full_doc_path, path)

with mkdocs_gen_files.open(full_doc / "SUMMARY.md", "w") as nav_file:
    nav_file.writelines(nav.build_literate_nav())
