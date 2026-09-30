"""Which file chooser opens, and the guarantee that one always does.

The desktop's own chooser lives in another process behind D-Bus, so these do
not open a dialog. What they check is the decision: that Quenchkey asks for the
portal when the desktop has one, leaves a deliberate choice alone, and falls
back to Qt's own dialog rather than to no dialog at all.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt5.QtWidgets")

from PyQt5.QtWidgets import QFileDialog  # noqa: E402

from quenchkey.ui import filechooser  # noqa: E402


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in (filechooser.MODE_ENV, "QT_QPA_PLATFORMTHEME", "QT_QPA_PLATFORM",
                 "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
                 "XDG_DATA_HOME", "XDG_DATA_DIRS"):
        monkeypatch.delenv(name, raising=False)
    filechooser.reset_cache()
    yield
    filechooser.reset_cache()


def install_portal(tmp_path, monkeypatch):
    """Lay out a desktop that has a portal, as a real session would."""
    services = tmp_path / "share" / "dbus-1" / "services"
    services.mkdir(parents=True)
    (services / f"{filechooser.PORTAL_SERVICE}.service").write_text("[D-BUS Service]\n")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")


# -- the decision -----------------------------------------------------------

def test_a_desktop_with_a_portal_gets_the_desktops_own_chooser(tmp_path, monkeypatch):
    install_portal(tmp_path, monkeypatch)
    assert filechooser.portal_installed() is True
    assert filechooser.configure() == filechooser.PORTAL_THEME
    assert os.environ["QT_QPA_PLATFORMTHEME"] == filechooser.PORTAL_THEME


def test_no_session_bus_means_no_portal(tmp_path, monkeypatch):
    install_portal(tmp_path, monkeypatch)
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS")
    assert filechooser.portal_installed() is False
    assert filechooser.configure() is None


def test_a_session_bus_without_the_portal_installed_is_not_enough(monkeypatch, tmp_path):
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path))
    assert filechooser.portal_installed() is False
    assert filechooser.configure() is None


def test_a_theme_the_user_chose_is_left_alone(tmp_path, monkeypatch):
    install_portal(tmp_path, monkeypatch)
    monkeypatch.setenv("QT_QPA_PLATFORMTHEME", "gtk3")
    assert filechooser.configure() is None
    assert os.environ["QT_QPA_PLATFORMTHEME"] == "gtk3"


def test_the_environment_can_force_qts_own_dialog(tmp_path, monkeypatch):
    install_portal(tmp_path, monkeypatch)
    monkeypatch.setenv(filechooser.MODE_ENV, "qt")
    assert filechooser.mode() == "qt"
    assert filechooser.configure() is None
    assert filechooser.using_portal() is False


def test_the_environment_can_force_the_portal(monkeypatch):
    """Without an installed service file, which is how a Flatpak looks."""
    monkeypatch.setenv(filechooser.MODE_ENV, "portal")
    assert filechooser.portal_installed() is False
    assert filechooser.configure() == filechooser.PORTAL_THEME


def test_a_headless_run_never_asks_for_a_portal(tmp_path, monkeypatch):
    install_portal(tmp_path, monkeypatch)
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    assert filechooser.headless() is True
    assert filechooser.configure() is None


def test_a_runtime_bus_socket_counts_as_a_session_bus(tmp_path, monkeypatch):
    install_portal(tmp_path, monkeypatch)
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS")
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "bus").write_text("")
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    assert filechooser.portal_installed() is True


# -- the guarantee ----------------------------------------------------------

def test_a_portal_that_never_answers_falls_back_to_qts_dialog(tmp_path, monkeypatch):
    """The failure that matters: a chooser that would never open.

    The service file says the portal can be started. If it then does not
    answer, using it anyway would leave the user clicking a button that does
    nothing, so the fallback has to be Qt's own dialog rather than none.
    """
    install_portal(tmp_path, monkeypatch)
    filechooser.configure()
    monkeypatch.setattr(filechooser, "_ping_portal", lambda timeout: False)
    filechooser.reset_cache()

    assert filechooser.using_portal() is False
    assert filechooser._options() & QFileDialog.DontUseNativeDialog


def test_a_portal_that_answers_is_used(tmp_path, monkeypatch):
    install_portal(tmp_path, monkeypatch)
    filechooser.configure()
    monkeypatch.setattr(filechooser, "_ping_portal", lambda timeout: True)
    filechooser.reset_cache()

    assert filechooser.using_portal() is True
    assert not (filechooser._options() & QFileDialog.DontUseNativeDialog)


def test_the_portal_is_pinged_once_per_session(tmp_path, monkeypatch):
    install_portal(tmp_path, monkeypatch)
    filechooser.configure()
    calls = []
    monkeypatch.setattr(filechooser, "_ping_portal",
                        lambda timeout: calls.append(timeout) or True)
    filechooser.reset_cache()

    assert filechooser.portal_responds() is True
    assert filechooser.portal_responds() is True
    assert len(calls) == 1


def test_a_broken_bus_is_survivable(monkeypatch):
    """Anything thrown while probing must not stop a dialog appearing."""
    from PyQt5 import QtDBus

    def explode():
        raise RuntimeError("the bus went away")

    monkeypatch.setattr(QtDBus.QDBusConnection, "sessionBus", staticmethod(explode))
    filechooser.reset_cache()
    assert filechooser._ping_portal(50) is False
    assert filechooser.portal_responds() is False


# -- the call sites ---------------------------------------------------------

def test_every_file_picker_goes_through_this_module():
    """No screen may reach for QFileDialog directly and miss the decision."""
    import pathlib
    ui = pathlib.Path(filechooser.__file__).parent
    offenders = [path.name for path in ui.glob("*.py")
                 if path.name != "filechooser.py"
                 and "QFileDialog" in path.read_text()]
    assert offenders == []


def test_the_vault_filter_matches_the_extension_vaults_actually_use():
    from quenchkey.vault import DEFAULT_VAULT_PATH
    import pathlib
    gate = (pathlib.Path(filechooser.__file__).parent / "gate.py").read_text()
    suffix = os.path.splitext(DEFAULT_VAULT_PATH)[1]
    assert f"(*{suffix})" in gate
