def test_database_models_register_core_tables(monkeypatch, protected_test_config):
    monkeypatch.chdir(protected_test_config.src_dir)

    import include.database.models  # noqa: F401
    from include.database.session import Base

    expected_tables = {
        "audit_entries",
        "banned_subnets",
        "document_revisions",
        "documents",
        "files",
        "keyrings",
        "nodes",
        "share_links",
        "users",
    }
    assert expected_tables <= set(Base.metadata.tables)


def test_fresh_create_all_contains_drive_schema(
    monkeypatch, protected_test_config, tmp_path
):
    monkeypatch.chdir(protected_test_config.src_dir)

    from sqlalchemy import create_engine, inspect

    import include.database.models  # noqa: F401
    from include.database.session import Base

    engine = create_engine(f"sqlite:///{tmp_path / 'fresh-drive.db'}")
    Base.metadata.create_all(engine)
    inspector = inspect(engine)

    assert "share_links" in inspector.get_table_names()
    assert {column["name"] for column in inspector.get_columns("users")} >= {
        "home_directory_id",
        "disk_quota",
    }
    engine.dispose()


def test_database_models_export_node_only(monkeypatch, protected_test_config):
    monkeypatch.chdir(protected_test_config.src_dir)

    import include.database.models as models
    from include.database.models import documents

    legacy_name = "Base" + "Object"

    assert models.Node is documents.Node
    assert "Node" in models.__all__
    assert "Node" in documents.__all__
    assert not hasattr(models, legacy_name)
    assert not hasattr(documents, legacy_name)
    assert legacy_name not in models.__all__
    assert legacy_name not in documents.__all__
