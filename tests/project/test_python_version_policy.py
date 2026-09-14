import ast
import pathlib
import tomllib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
PYTHON_SOURCE_ROOTS = (
    PROJECT_ROOT / "src",
    PROJECT_ROOT / "tests",
    PROJECT_ROOT / "tools",
)
LEGACY_FUTURE_ANNOTATION_PATHS = {
    pathlib.Path("src/include/database/models/shares.py"),
    pathlib.Path("src/include/domains/drive/handlers.py"),
    pathlib.Path("src/include/domains/drive/homes.py"),
    pathlib.Path("src/include/domains/drive/quota.py"),
    pathlib.Path("src/include/domains/drive/shares.py"),
    pathlib.Path("src/include/domains/transfers/consumer.py"),
    pathlib.Path("src/include/domains/transfers/handlers.py"),
    pathlib.Path("src/include/domains/transfers/settings.py"),
    pathlib.Path("src/include/domains/transfers/store.py"),
    pathlib.Path("src/include/domains/transfers/tickets.py"),
    pathlib.Path("src/include/extensions/thesis_attack_lab/_extension.py"),
    pathlib.Path("tests/test_drive_features.py"),
    pathlib.Path("tests/test_thesis_attack_lab.py"),
    pathlib.Path("tests/test_transfer_data_plane.py"),
}


def test_project_requires_python_3_14_or_newer():
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    assert pyproject["project"]["requires-python"] == ">=3.14"


def test_python_sources_do_not_enable_postponed_annotations():
    future_annotation_imports = []

    for source_root in PYTHON_SOURCE_ROOTS:
        for source_path in source_root.rglob("*.py"):
            if ".venv" in source_path.parts or source_path.is_relative_to(
                PROJECT_ROOT / "src" / "certtools"
            ):
                continue

            module = ast.parse(source_path.read_text(encoding="utf-8"))
            for node in module.body:
                if not isinstance(node, ast.ImportFrom) or node.module != "__future__":
                    continue
                if any(alias.name == "annotations" for alias in node.names):
                    future_annotation_imports.append(
                        source_path.relative_to(PROJECT_ROOT)
                    )

    assert set(future_annotation_imports) == LEGACY_FUTURE_ANNOTATION_PATHS
