from reverser.gui.main_window import _display_release_version, _is_newer_release


def test_release_version_comparison_handles_v_prefix() -> None:
    assert _is_newer_release("v0.16.1", "0.16.0")
    assert not _is_newer_release("v0.16.0", "0.16.0")
    assert not _is_newer_release("v0.15.9", "0.16.0")


def test_release_version_comparison_ignores_prerelease_suffix_for_core_version() -> None:
    assert _is_newer_release("v0.17.0-alpha.1", "0.16.0")
    assert not _is_newer_release("v0.16.0-beta.1", "0.16.0")


def test_display_release_version_strips_semver_v_prefix_only() -> None:
    assert _display_release_version("v1.2.3") == "1.2.3"
    assert _display_release_version("preview-build") == "preview-build"
