"""Preferences, autostart and uninstall.

These decide where somebody's files land and what happens when they close the
window, so the interesting cases are the ones where a stored preference has
gone stale or cannot be honoured.
"""

from __future__ import annotations

import os

import pytest

from quenchkey import autostart, settings as settings_mod, uninstall


@pytest.fixture()
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    store = settings_mod.Settings()
    settings_mod.use(store)
    yield store
    settings_mod.use(None)


# -- storage ----------------------------------------------------------------

def test_defaults_apply_before_anything_is_written(config):
    assert config.get("close_action") == settings_mod.CLOSE_ASK
    assert config.output_rule("extracted") == (settings_mod.ASK, "")
    assert not os.path.exists(config.path)


def test_settings_survive_a_restart(config, tmp_path):
    config.set("close_action", settings_mod.CLOSE_TRAY)
    config.set_output_rule("shares", settings_mod.FIXED, str(tmp_path))

    reopened = settings_mod.Settings(config.path)
    assert reopened.get("close_action") == settings_mod.CLOSE_TRAY
    assert reopened.output_rule("shares") == (settings_mod.FIXED, str(tmp_path))


def test_the_file_is_readable_only_by_its_owner(config):
    config.set("close_action", settings_mod.CLOSE_QUIT)
    assert os.stat(config.path).st_mode & 0o777 == 0o600


def test_only_known_preferences_are_written(config, tmp_path):
    """It lives outside the vault, so what goes in it matters.

    Checked structurally rather than by scanning the text for forbidden
    words: the file legitimately contains folder paths, and a path can
    contain any word at all.
    """
    import json

    folder = tmp_path / "documents"
    folder.mkdir()
    config.set_output_rule("extracted", settings_mod.FIXED, str(folder))
    stored = json.load(open(config.path))

    assert set(stored) <= set(settings_mod.DEFAULTS)
    assert set(stored["outputs"]) <= set(settings_mod.OUTPUT_KINDS)
    for rule in stored["outputs"].values():
        assert set(rule) == {"mode", "path"}
        assert rule["mode"] in (settings_mod.ASK, settings_mod.FIXED,
                                settings_mod.BESIDE)
        assert rule["path"] in ("", str(folder))


def test_a_damaged_file_falls_back_to_defaults(config):
    config.save()
    with open(config.path, "w") as fh:
        fh.write("{ this is not json")

    recovered = settings_mod.Settings(config.path)
    assert recovered.get("close_action") == settings_mod.CLOSE_ASK


def test_unknown_keys_are_ignored(config):
    import json
    config.save()
    with open(config.path, "w") as fh:
        json.dump({"close_action": settings_mod.CLOSE_QUIT,
                   "something_else": "ignored"}, fh)

    reopened = settings_mod.Settings(config.path)
    assert reopened.get("close_action") == settings_mod.CLOSE_QUIT
    assert reopened.get("something_else") is None


# -- output rules -----------------------------------------------------------

def test_every_output_kind_has_a_workable_default(config):
    for kind, spec in settings_mod.OUTPUT_KINDS.items():
        mode, _path = config.output_rule(kind)
        assert mode in spec["modes"], kind


def test_a_remembered_folder_that_has_gone_falls_back_to_asking(config, tmp_path):
    """Rather than failing at the moment somebody tries to save something."""
    folder = tmp_path / "somewhere"
    folder.mkdir()
    config.set_output_rule("certificates", settings_mod.FIXED, str(folder))
    assert config.output_rule("certificates")[0] == settings_mod.FIXED

    folder.rmdir()
    assert config.output_rule("certificates") == (settings_mod.ASK, "")


def test_a_mode_a_kind_does_not_offer_is_refused(config):
    with pytest.raises(ValueError):
        config.set_output_rule("certificates", settings_mod.BESIDE)


def test_an_unknown_kind_is_refused(config):
    with pytest.raises(KeyError):
        config.output_rule("nonsense")


def test_resetting_puts_every_kind_back(config, tmp_path):
    config.set_output_rule("shares", settings_mod.FIXED, str(tmp_path))
    config.reset_outputs()
    assert config.output_rule("shares") == (settings_mod.ASK, "")


# -- autostart --------------------------------------------------------------

def test_autostart_writes_one_ordinary_desktop_file(config):
    assert autostart.enabled() is False
    path = autostart.enable()

    assert autostart.enabled() is True
    body = open(path).read()
    assert body.startswith("[Desktop Entry]")
    assert "Name=Quenchkey" in body
    assert "Exec=" in body


def test_autostart_can_ask_for_a_minimised_start(config):
    autostart.enable(minimised=True)
    assert "--minimised" in open(autostart.desktop_path()).read()


def test_autostart_is_removable_and_removing_twice_is_fine(config):
    autostart.enable()
    autostart.disable()
    autostart.disable()
    assert autostart.enabled() is False


def test_autostart_does_not_store_a_passphrase(config):
    """Starting on login opens the unlock screen like any other launch."""
    autostart.enable()
    body = open(autostart.desktop_path()).read().lower()
    assert "passphrase" not in body
    assert "password" not in body


# -- uninstall --------------------------------------------------------------

def test_uninstall_reports_when_there_is_nothing_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(uninstall, "PREFIXES", (str(tmp_path / "nowhere"),))
    report = uninstall.describe()

    assert report.found is False
    assert uninstall.run().ok is False


def test_uninstall_refuses_a_prefix_it_cannot_write(monkeypatch, tmp_path):
    prefix = tmp_path / "usr-local"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "bin" / "quenchkey").write_text("#!/bin/sh\n")
    monkeypatch.setattr(uninstall, "PREFIXES", (str(prefix),))
    monkeypatch.setattr(uninstall.os, "access", lambda *a, **k: False)

    report = uninstall.describe()
    assert report.found and not report.writable
    assert "root" in report.detail
    result = uninstall.run()
    assert result.ok is False
    # And it left the installation alone rather than half-removing it.
    assert (prefix / "bin" / "quenchkey").exists()


def test_uninstall_never_lists_the_vault_among_what_it_removes(tmp_path):
    """Removing the application must not touch a single key."""
    for path in uninstall.targets(str(tmp_path)):
        assert ".qkey" not in os.path.basename(path).replace("quenchkey.xml", "")
        assert "vault" not in path
        assert not path.endswith(".qkv")


def test_uninstall_removes_what_the_installer_put_down(monkeypatch, tmp_path):
    prefix = tmp_path / "local"
    for relative in ("bin/quenchkey", "bin/quenchkey-recover",
                     "share/applications/quenchkey.desktop",
                     "share/mime/packages/quenchkey.xml"):
        target = prefix / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    (prefix / "lib" / "quenchkey" / "venv").mkdir(parents=True)

    monkeypatch.setattr(uninstall, "PREFIXES", (str(prefix),))
    monkeypatch.setattr(uninstall, "_stop_timer", lambda: None)
    monkeypatch.setattr(uninstall, "_refresh_caches", lambda prefix: None)

    result = uninstall.run()
    assert result.ok, result.detail
    assert not (prefix / "lib" / "quenchkey").exists()
    assert not (prefix / "bin" / "quenchkey").exists()


# -- the helper every save path goes through --------------------------------

@pytest.fixture()
def destinations(config):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PyQt5.QtWidgets")
    from quenchkey.ui import destinations as module
    return module


def test_a_fixed_folder_is_used_without_asking(destinations, config, tmp_path,
                                               monkeypatch):
    folder = tmp_path / "always-here"
    folder.mkdir()
    config.set_output_rule("certificates", settings_mod.FIXED, str(folder))
    monkeypatch.setattr(destinations.filechooser, "choose_directory",
                        lambda *a, **k: pytest.fail("should not have asked"))

    assert destinations.folder_for("certificates", None, "x") == str(folder)


def test_asking_goes_to_the_desktops_own_chooser(destinations, config, tmp_path):
    asked = []
    destinations.filechooser.choose_directory = (
        lambda parent, title, start: asked.append(title) or str(tmp_path))

    assert destinations.folder_for("certificates", None, "Pick one") == str(tmp_path)
    assert asked == ["Pick one"]


def test_beside_means_next_to_the_source_file(destinations, config, tmp_path):
    source = tmp_path / "somewhere" / "locked.qkey"
    source.parent.mkdir()
    source.write_text("x")

    assert destinations.folder_for("locked", None, "x", beside=str(source)) == \
        str(source.parent)


def test_a_fixed_folder_never_overwrites(destinations, config, tmp_path):
    """Nobody was asked, so nobody agreed to replace anything."""
    folder = tmp_path / "out"
    folder.mkdir()
    (folder / "report.json").write_text("the first one")
    config.set_output_rule("certificates", settings_mod.FIXED, str(folder))

    chosen = destinations.file_for("certificates", None, "x", "report.json")
    assert chosen == str(folder / "report (2).json")
    assert (folder / "report.json").read_text() == "the first one"


def test_a_dismissed_chooser_reports_nothing_chosen(destinations, config):
    destinations.filechooser.choose_directory = lambda *a, **k: None
    assert destinations.folder_for("certificates", None, "x") is None


def test_the_description_matches_the_rule(destinations, config, tmp_path):
    assert "asked" in destinations.describe("certificates")
    config.set_output_rule("certificates", settings_mod.FIXED, str(tmp_path))
    assert str(tmp_path) in destinations.describe("certificates")
    assert "beside" in destinations.describe("locked").lower()
