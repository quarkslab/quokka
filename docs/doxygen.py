import subprocess
import shutil
import logging
from pathlib import Path

from mkdocs.exceptions import PluginError


def generate_cpp_documentation(config) -> None:
    """Function called by MkDocs on post_build event to generate
    the Doxygen documentation for the C++ code.

    This is poorly integrated with MkDocs (and Material-Mkdocs) but at
    least it works.

    :param config: Configuration from MkDocs
    """

    logger = logging.getLogger("mkdocs")
    logger.info(f"Generating Doxygen Documentation")

    project_directory: Path = Path(".").resolve()

    # Let's copy the doxygen file before modifying it
    config_file = project_directory / "doxygen.cfg"
    shutil.copy(config_file, config_file.with_name("doxygen_current.cfg"))

    with open(config_file.with_name("doxygen_current.cfg"), "a") as file:
        print(f"OUTPUT_DIRECTORY={config['site_dir']}", file=file)
        print(f"HTML_OUTPUT=reference/cpp", file=file)

    # Create the directory for the CPP documentation before
    (Path(config["site_dir"]) / "reference").mkdir(exist_ok=True, parents=True)

    # Call Doxygen: since it's verbose, prevent anything to be displayed.
    try:
        subprocess.check_call([
            "doxygen",
            "doxygen_current.cfg"
        ],
            cwd=project_directory,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        raise PluginError("Unable to call doxygen")
