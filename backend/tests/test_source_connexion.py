from pathlib import Path

from app.analysis.context import (
    AuthState,
    NormalizedEndpoint,
    NormalizedOpenAPI,
    NormalizedOperation,
)
from app.analysis.source import load_source_from_memory, normalize_source_tree
from app.analysis.source.connexion import has_connexion_registration
from app.analysis.source.parser import parse_source_file
from app.evaluation.connexion_protocol_v1 import evaluate_connexion_protocol
from app.evaluation.runner import run_single_case_analysis


def test_connexion_routes_map_from_dotted_operation_ids_without_execution() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "import connexion\n"
                "service = connexion.App(__name__)\n"
                "service.add_api('openapi.yml')\n"
            ),
            "api_views/books.py": (
                "def list_books():\n"
                "    return []\n\n"
                "def get_book(book_id):\n"
                "    token_validator(request.headers.get('Authorization'))\n"
                "    return {'id': book_id}\n\n"
                "raise RuntimeError('source must never execute')\n"
            ),
        }
    )
    specification = NormalizedOpenAPI(
        endpoints=(
            NormalizedEndpoint(
                path="/books",
                operations=(
                    NormalizedOperation(
                        method="get",
                        path="/books",
                        operation_id="api_views.books.list_books",
                    ),
                ),
            ),
            NormalizedEndpoint(
                path="/books/{book_id}",
                operations=(
                    NormalizedOperation(
                        method="get",
                        path="/books/{book_id}",
                        operation_id="api_views.books.get_book",
                    ),
                ),
            ),
        )
    )

    tree = normalize_source_tree(source, specification=specification)

    assert [(endpoint.method, endpoint.path) for endpoint in tree.endpoints] == [
        ("get", "/books"),
        ("get", "/books/{book_id}"),
    ]
    by_handler = {endpoint.handler_name: endpoint for endpoint in tree.endpoints}
    assert by_handler["list_books"].framework == "connexion"
    assert by_handler["list_books"].auth_state == AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE
    assert by_handler["get_book"].auth_state == AuthState.AUTH_PRESENT
    assert by_handler["get_book"].parameters[0].is_path_param


def test_connexion_operation_id_does_not_guess_unqualified_function_names() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "import connexion\napp = connexion.App(__name__)\napp.add_api('api.yml')\n"
            ),
            "handlers.py": "def list_books():\n    return []\n",
        }
    )
    specification = NormalizedOpenAPI(
        endpoints=(
            NormalizedEndpoint(
                path="/books",
                operations=(
                    NormalizedOperation(method="get", path="/books", operation_id="list_books"),
                ),
            ),
        )
    )

    tree = normalize_source_tree(source, specification=specification)

    assert tree.endpoints == ()


def test_connexion_operation_id_does_not_match_a_different_nested_package() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "import connexion\napp = connexion.App(__name__)\napp.add_api('api.yml')\n"
            ),
            "other/api_views/books.py": "def list_books():\n    return []\n",
        }
    )
    specification = NormalizedOpenAPI(
        endpoints=(
            NormalizedEndpoint(
                path="/books",
                operations=(
                    NormalizedOperation(
                        method="get",
                        path="/books",
                        operation_id="api_views.books.list_books",
                    ),
                ),
            ),
        )
    )

    tree = normalize_source_tree(source, specification=specification)

    assert tree.endpoints == ()


def test_unrelated_add_api_receiver_is_not_treated_as_connexion_registration() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "import connexion\n"
                "app = connexion.App(__name__)\n"
                "unrelated = object()\n"
                "unrelated.add_api('openapi.yml')\n"
            ),
            "handlers/books.py": "def list_books():\n    return []\n",
        }
    )
    config = source.files[0]
    parsed = parse_source_file(config.content, config.relative_path, config.content_hash)

    assert has_connexion_registration(parsed) is False


def test_connexion_import_and_variable_aliases_are_supported() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "from connexion import App as ConnexionApp\n"
                "service = ConnexionApp(__name__)\n"
                "application = service\n"
                "application.add_api('openapi.yml')\n"
            )
        }
    )
    config = source.files[0]
    parsed = parse_source_file(config.content, config.relative_path, config.content_hash)

    assert has_connexion_registration(parsed) is True


def test_direct_connexion_registration_is_supported() -> None:
    source = load_source_from_memory(
        {"config.py": "import connexion\nconnexion.App(__name__).add_api('openapi.yml')\n"}
    )
    config = source.files[0]
    parsed = parse_source_file(config.content, config.relative_path, config.content_hash)

    assert has_connexion_registration(parsed) is True


def test_conditional_shadowing_of_connexion_rejects_later_registration() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "import connexion\n"
                "if use_other_library:\n"
                "    connexion = object()\n"
                "app = connexion.App(__name__)\n"
                "app.add_api('openapi.yml')\n"
            )
        }
    )
    config = source.files[0]
    parsed = parse_source_file(config.content, config.relative_path, config.content_hash)

    assert has_connexion_registration(parsed) is False


def test_conditional_function_definition_shadowing_is_conservative() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "import connexion\n"
                "if use_other_library:\n"
                "    def connexion():\n"
                "        return object()\n"
                "app = connexion.App(__name__)\n"
                "app.add_api('openapi.yml')\n"
            )
        }
    )
    config = source.files[0]
    parsed = parse_source_file(config.content, config.relative_path, config.content_hash)

    assert has_connexion_registration(parsed) is False


def test_branch_only_application_assignment_does_not_leak_after_branch() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "import connexion\n"
                "if enabled:\n"
                "    app = connexion.App(__name__)\n"
                "app.add_api('openapi.yml')\n"
            )
        }
    )
    config = source.files[0]
    parsed = parse_source_file(config.content, config.relative_path, config.content_hash)

    assert has_connexion_registration(parsed) is False


def test_registration_inside_branch_with_branch_local_app_is_supported() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "import connexion\n"
                "if enabled:\n"
                "    app = connexion.App(__name__)\n"
                "    app.add_api('openapi.yml')\n"
            )
        }
    )
    config = source.files[0]
    parsed = parse_source_file(config.content, config.relative_path, config.content_hash)

    assert has_connexion_registration(parsed) is True


def test_function_parameter_shadowing_imported_connexion_is_rejected() -> None:
    source = load_source_from_memory(
        {
            "config.py": (
                "import connexion\n"
                "def configure(connexion):\n"
                "    app = connexion.App(__name__)\n"
                "    app.add_api('openapi.yml')\n"
            )
        }
    )
    config = source.files[0]
    parsed = parse_source_file(config.content, config.relative_path, config.content_hash)

    assert has_connexion_registration(parsed) is False


def test_dynamic_factory_and_reassigned_application_are_conservatively_rejected() -> None:
    sources = (
        "import connexion\napp = build_app()\napp.add_api('openapi.yml')\n",
        (
            "import connexion\napp = connexion.App(__name__)\n"
            "app = get_other_object()\napp.add_api('openapi.yml')\n"
        ),
        (
            "def local_import():\n    import connexion\n"
            "app = connexion.App(__name__)\napp.add_api('openapi.yml')\n"
        ),
        (
            "import connexion\nconnexion = make_other_object()\n"
            "app = connexion.App(__name__)\napp.add_api('openapi.yml')\n"
        ),
        (
            "import connexion\napp = connexion.App(__name__)\n"
            "if condition:\n    app = make_other_object()\n"
            "    app.add_api('openapi.yml')\n"
        ),
    )
    for content in sources:
        source = load_source_from_memory({"config.py": content})
        config = source.files[0]
        parsed = parse_source_file(config.content, config.relative_path, config.content_hash)
        assert has_connexion_registration(parsed) is False


def test_connexion_protocol_v1_has_independent_fixture_expectations() -> None:
    result = evaluate_connexion_protocol()

    assert result["protocol_version"] == "connexion-contract-assisted-v1"
    assert result["case_count"] == 5
    assert result["registration"] == {
        "tp": 3,
        "fp": 0,
        "fn": 0,
        "tn": 2,
        "precision": 1.0,
        "recall": 1.0,
    }
    assert result["mapping"] == {
        "tp": 2,
        "fp": 0,
        "fn": 0,
        "precision": 1.0,
        "recall": 1.0,
    }
    assert result["evidence_provenance"] == {"passed": 2, "total": 2, "accuracy": 1.0}
    assert result["failure_categories"] == {}


def test_connexion_protocol_v1_results_are_reproducible() -> None:
    assert evaluate_connexion_protocol() == evaluate_connexion_protocol()


def test_source_only_research_does_not_infer_routes_from_openapi(tmp_path: Path) -> None:
    spec_path = tmp_path / "openapi.yaml"
    spec_path.write_text(
        "openapi: 3.0.3\n"
        "info: {title: Sample, version: '1.0'}\n"
        "paths:\n"
        "  /books:\n"
        "    get:\n"
        "      operationId: handlers.books.list_books\n",
        encoding="utf-8",
    )
    source_dir = tmp_path / "source"
    (source_dir / "handlers").mkdir(parents=True)
    (source_dir / "config.py").write_text(
        "import connexion\napp = connexion.App(__name__)\napp.add_api('openapi.yaml')\n",
        encoding="utf-8",
    )
    (source_dir / "handlers" / "books.py").write_text(
        "def list_books():\n    return []\n",
        encoding="utf-8",
    )

    _, result = run_single_case_analysis(spec_path, source_dir)

    # This handler has no source-level route declaration. Its endpoint exists only in
    # OpenAPI and must not enter the independent SOURCE_ONLY research condition.
    assert result.source_only_findings == ()
