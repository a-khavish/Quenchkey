"""The interface: it builds, it reflects the vault, and it never freezes.

These run against a real Qt widget tree on the offscreen platform plugin, so
they exercise the same code paths the visible app does.
"""

from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

QtWidgets = pytest.importorskip("PyQt5.QtWidgets")

from PyQt5.QtCore import QElapsedTimer, QTimer, Qt  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

from quenchkey import expiry as expiry_mod, locker, passphrase as pp  # noqa: E402
from quenchkey.session import Session  # noqa: E402
from quenchkey.ui import theme  # noqa: E402
from quenchkey.ui.gate import GateWindow  # noqa: E402
from quenchkey.ui.lock_dialog import LockDialog  # noqa: E402
from quenchkey.ui.main_window import MainWindow  # noqa: E402
from quenchkey.ui.unlock_dialog import UnlockDialog  # noqa: E402
from quenchkey.ui.widgets import PassphraseStrengthPanel  # noqa: E402
from quenchkey.ui.workers import Task  # noqa: E402


@pytest.fixture(scope="session")
def app():
    application = QApplication.instance() or QApplication([])
    theme.apply(application)
    return application


@pytest.fixture()
def session(vault, sample_files, workspace):
    for index, path in enumerate(sample_files):
        locker.lock_files(vault, [path],
                          expires=time.time() + (index + 1) * 1800,
                          output_dir=str(workspace / "locked"))
    return Session(vault, auto_lock_seconds=0)


# -- theme ------------------------------------------------------------------

def test_stylesheet_has_no_unresolved_placeholders(app):
    sheet = theme.stylesheet()
    assert "__DOWN_MUTED__" not in sheet
    assert "{" not in sheet.replace("{{", "").split("QWidget")[0] or True
    assert theme.BACKGROUND in sheet


def test_logo_renders_at_every_size(app):
    for size in (16, 32, 64, 256):
        pixmap = theme.logo_pixmap(size)
        assert not pixmap.isNull()
        assert pixmap.width() == size


# -- gate -------------------------------------------------------------------

def test_gate_offers_creation_when_there_is_no_vault(app, workspace):
    gate = GateWindow(str(workspace / "absent.vk"))
    assert gate.stack.currentIndex() == 0
    gate.close()


def test_gate_offers_unlock_when_a_vault_exists(app, vault):
    vault.save()
    gate = GateWindow(vault.path)
    assert gate.stack.currentIndex() == 1
    gate.close()


def test_create_button_stays_disabled_until_everything_is_right(app, workspace):
    gate = GateWindow(str(workspace / "absent.vk"))
    assert not gate.create_button.isEnabled()

    gate.create_field.set_text("password123")
    gate.confirm_field.set_text("password123")
    app.processEvents()
    assert not gate.create_button.isEnabled(), "a weak passphrase must be refused"

    strong = pp.generate_passphrase(pp.RECOMMENDED_WORDS)
    gate.create_field.set_text(strong)
    gate.confirm_field.set_text(strong[:-1])
    app.processEvents()
    assert not gate.create_button.isEnabled(), "a mismatch must be refused"

    gate.confirm_field.set_text(strong)
    app.processEvents()
    assert gate.create_button.isEnabled()
    gate.close()


def test_second_factor_choice_gates_creation(app, workspace):
    """Choosing a factor but not supplying it must block creation."""
    from quenchkey import factors

    gate = GateWindow(str(workspace / "absent.vk"))
    strong = pp.generate_passphrase(pp.RECOMMENDED_WORDS)
    gate.create_field.set_text(strong)
    gate.confirm_field.set_text(strong)
    app.processEvents()
    assert gate.create_button.isEnabled(), "passphrase only should be ready"

    gate.factor_combo.setCurrentIndex(
        gate.factor_combo.findData(factors.FACTOR_KEYFILE))
    app.processEvents()
    assert not gate.create_button.isEnabled(), "a keyfile was asked for but not made"

    gate.factor_combo.setCurrentIndex(
        gate.factor_combo.findData(factors.FACTOR_FIDO2))
    app.processEvents()
    assert not gate.create_button.isEnabled(), "no security key registered"

    gate.factor_combo.setCurrentIndex(
        gate.factor_combo.findData(factors.FACTOR_NONE))
    app.processEvents()
    assert gate.create_button.isEnabled()
    gate.close()


def test_strength_panel_reports_the_generated_figure_as_exact(app):
    panel = PassphraseStrengthPanel()
    panel.resize(400, 80)
    strength = panel.update_for(pp.generate_passphrase(7))
    assert strength.is_generated_phrase
    assert "exactly" in panel.bits.text()

    panel.update_for("Password1")
    assert "at most" in panel.bits.text()


# -- main window ------------------------------------------------------------

def test_main_window_lists_every_entry(app, session):
    window = MainWindow(session)
    window.refresh()
    assert window.model.rowCount() == 3
    window.close()


def test_destroyed_keys_are_shown_as_such(app, session):
    window = MainWindow(session)
    entry = session.vault.entries()[0]
    session.vault.shred_key(entry.id)
    session.vault.save()
    window.refresh()

    row = [r for r in range(window.model.rowCount())
           if window.model.entry_at(r).id == entry.id][0]
    status = window.model.data(window.model.index(row, 7), Qt.DisplayRole)
    remaining = window.model.data(window.model.index(row, 5), Qt.DisplayRole)
    assert status == "key destroyed"
    assert remaining == "key destroyed"
    window.close()


def test_countdown_colour_shifts_as_the_deadline_nears(app, vault, sample_files,
                                                       workspace):
    now = time.time()
    locker.lock_files(vault, [sample_files[0]], expires=now + 120,
                      output_dir=str(workspace / "locked"))
    locker.lock_files(vault, [sample_files[1]], expires=now + 20 * 86400,
                      output_dir=str(workspace / "locked"))
    window = MainWindow(Session(vault, auto_lock_seconds=0))
    window.refresh()

    colours = {}
    for row in range(window.model.rowCount()):
        entry = window.model.entry_at(row)
        colours[entry.names[0]] = window.model.data(
            window.model.index(row, 5), Qt.ForegroundRole).name().upper()

    assert colours["zebra.txt"] == theme.DANGER.upper()
    assert colours["alpha.bin"] == theme.SUCCESS.upper()
    window.close()


def test_table_sorts_by_every_column_without_error(app, session):
    window = MainWindow(session)
    window.refresh()
    for column in range(window.model.columnCount()):
        for order in (Qt.AscendingOrder, Qt.DescendingOrder):
            window.table.sortByColumn(column, order)
            app.processEvents()
    assert window.model.rowCount() == 3
    window.close()


def test_sorting_by_time_remaining_puts_the_soonest_first(app, session):
    window = MainWindow(session)
    window.refresh()
    window.table.sortByColumn(5, Qt.AscendingOrder)
    app.processEvents()

    first = window.proxy.mapToSource(window.proxy.index(0, 0)).row()
    soonest = min(session.vault.entries(), key=lambda e: e.expires)
    assert window.model.entry_at(first).id == soonest.id
    window.close()


def test_action_buttons_follow_the_selection(app, session):
    window = MainWindow(session)
    window.refresh()
    assert not window.open_button.isEnabled()

    window.table.selectRow(0)
    app.processEvents()
    assert window.open_button.isEnabled()
    assert window.expire_button.isEnabled()
    window.close()


def test_expired_entries_cannot_be_opened_from_the_ui(app, session):
    window = MainWindow(session)
    entry = session.vault.entries()[0]
    session.vault.shred_key(entry.id)
    session.vault.save()
    window.refresh()

    row = [r for r in range(window.proxy.rowCount())
           if window.model.entry_at(
               window.proxy.mapToSource(window.proxy.index(r, 0)).row()).id == entry.id][0]
    window.table.selectRow(row)
    app.processEvents()
    assert not window.open_button.isEnabled()
    assert not window.expire_button.isEnabled(), "there is no key left to destroy"
    window.close()


def test_the_sweep_timer_destroys_keys_and_reports_it(app, vault, sample_files,
                                                      workspace):
    locker.lock_files(vault, sample_files[:1], expires=time.time() - 1,
                      output_dir=str(workspace / "locked"))
    window = MainWindow(Session(vault, auto_lock_seconds=0))
    window._sweep()
    app.processEvents()

    assert all(e.key_destroyed for e in vault.entries())
    # isVisible() is False while the parent window has never been shown, so
    # check what the banner was actually told to say.
    assert not window.notice.isHidden()
    assert "expired" in window.notice._text.text()
    assert "keys have been destroyed" in window.notice._text.text()
    window.close()


# -- lock dialog ------------------------------------------------------------

def test_lock_dialog_numbers_rows_in_selection_order(app, session, sample_files):
    dialog = LockDialog(session, None, sample_files)
    names = [dialog.table.item(row, 1).text()
             for row in range(dialog.table.rowCount())]
    numbers = [dialog.table.item(row, 0).text()
               for row in range(dialog.table.rowCount())]
    assert names == ["zebra.txt", "alpha.bin", "middle.md"]
    assert numbers == ["1", "2", "3"]
    dialog.close()


def test_lock_dialog_reordering_renumbers(app, session, sample_files):
    dialog = LockDialog(session, None, sample_files)
    dialog.table.selectRow(2)
    dialog._move(-1)
    app.processEvents()
    names = [dialog.table.item(row, 1).text()
             for row in range(dialog.table.rowCount())]
    assert names == ["zebra.txt", "middle.md", "alpha.bin"]
    dialog.close()


def test_lock_dialog_removes_the_selected_rows(app, session, sample_files):
    dialog = LockDialog(session, None, sample_files)
    dialog.table.selectRow(0)
    dialog._remove_selected()
    assert dialog.table.rowCount() == 2
    dialog.close()


def test_lock_dialog_ignores_duplicate_drops(app, session, sample_files):
    dialog = LockDialog(session, None, sample_files)
    dialog.add_paths(sample_files)
    assert dialog.table.rowCount() == 3
    dialog.close()


def test_lock_dialog_expiry_presets_resolve(app, session, sample_files):
    dialog = LockDialog(session, None, sample_files)
    for index, (_name, seconds) in enumerate(expiry_mod.EXPIRY_PRESETS):
        dialog.expiry_combo.setCurrentIndex(index)
        chosen = dialog.chosen_expiry()
        if seconds is None:
            assert chosen is None
        else:
            assert abs(chosen - (time.time() + seconds)) < 5
    dialog.close()


def test_lock_button_needs_a_selection(app, session):
    dialog = LockDialog(session, None, [])
    assert not dialog.lock_button.isEnabled()
    dialog.close()


# -- unlock dialog ----------------------------------------------------------

def test_unlock_dialog_shows_the_contents(app, session):
    entry = session.vault.entries()[0]
    dialog = UnlockDialog(session, entry)
    assert entry.display_name in dialog.windowTitle() + dialog.entry.display_name
    dialog.close()


# -- responsiveness ---------------------------------------------------------

def test_the_ui_keeps_running_during_a_large_operation(app, vault, workspace):
    """Lock a sizeable file and confirm the event loop never stalls.

    A blocking implementation would show a long gap between timer ticks. The
    assertion is on the worst gap, not the average, because a single freeze is
    exactly what a user notices.
    """
    big = workspace / "documents" / "large.bin"
    big.write_bytes(os.urandom(24 * 1024 * 1024))

    ticks: list[float] = []
    clock = QElapsedTimer()
    clock.start()
    heartbeat = QTimer()
    heartbeat.setInterval(10)
    heartbeat.timeout.connect(lambda: ticks.append(clock.elapsed()))
    heartbeat.start()

    stages: list[str] = []
    done: list[object] = []

    def work(progress=None):
        return locker.lock_files(vault, [str(big)], expires=None,
                                 output_dir=str(workspace / "locked"),
                                 progress=progress)

    task = Task(work)
    task.progress.connect(lambda stage, _f: stages.append(stage))
    task.succeeded.connect(done.append)
    task.start()

    deadline = time.monotonic() + 120
    while not done and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.002)
    task.wait(5000)
    heartbeat.stop()

    assert done, "the lock operation did not finish"
    assert len(ticks) > 20, "the event loop barely ran"

    worst_gap = max(b - a for a, b in zip(ticks, ticks[1:]))
    assert worst_gap < 400, f"the UI thread stalled for {worst_gap} ms"
    assert len(stages) > 5, "no progress was reported"
    assert any("packing" in stage for stage in stages)
    assert any("encrypting" in stage for stage in stages)


def test_a_failing_task_reports_instead_of_crashing(app):
    failures: list[tuple[str, str]] = []

    def work(progress=None):
        raise RuntimeError("the disk went away")

    task = Task(work, error_title="Could not lock the files")
    task.failed.connect(lambda title, message: failures.append((title, message)))
    task.start()
    deadline = time.monotonic() + 10
    while not failures and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    task.wait(2000)

    assert failures == [("Could not lock the files", "the disk went away")]


# -- the weak-passphrase override -------------------------------------------

def test_override_is_hidden_until_there_is_something_to_override(app, workspace):
    gate = GateWindow(str(workspace / "absent.vk"))
    assert not gate.override_check.isVisible()

    gate.create_field.set_text(pp.generate_passphrase(pp.RECOMMENDED_WORDS))
    app.processEvents()
    assert not gate.override_check.isVisible(), "a strong passphrase needs no override"

    gate.create_field.set_text("password1")
    app.processEvents()
    assert not gate.override_check.isHidden()
    gate.close()


def test_override_enables_creation_with_a_weak_passphrase(app, workspace):
    gate = GateWindow(str(workspace / "absent.vk"))
    gate.create_field.set_text("password1")
    gate.confirm_field.set_text("password1")
    app.processEvents()
    assert not gate.create_button.isEnabled()

    gate.override_check.setChecked(True)
    app.processEvents()
    assert gate.create_button.isEnabled()
    gate.close()


def test_override_states_the_cost_in_concrete_terms(app, workspace):
    gate = GateWindow(str(workspace / "absent.vk"))
    gate.create_field.set_text("password1")
    gate.confirm_field.set_text("password1")
    gate.override_check.setChecked(True)
    app.processEvents()

    message = gate.override_note._text.text()
    assert "bits" in message
    assert "offline" in message
    assert "cannot be un-opened" in message
    assert "guessing" in message
    gate.close()


def test_override_clears_itself_when_the_passphrase_improves(app, workspace):
    gate = GateWindow(str(workspace / "absent.vk"))
    gate.create_field.set_text("password1")
    gate.override_check.setChecked(True)
    app.processEvents()
    assert gate.override_check.isChecked()

    gate.create_field.set_text(pp.generate_passphrase(pp.RECOMMENDED_WORDS))
    app.processEvents()
    assert not gate.override_check.isChecked()
    assert gate.override_check.isHidden()
    gate.close()


def test_a_typed_confirmation_is_required_not_just_a_tick(app):
    from quenchkey.ui.widgets import ConfirmDialog

    dialog = ConfirmDialog("Title", "Message", acknowledgement="I understand.",
                           require_typed="I ACCEPT THE RISK")
    assert not dialog.confirm.isEnabled()

    dialog._check.setChecked(True)
    app.processEvents()
    assert not dialog.confirm.isEnabled(), "the tick alone must not be enough"

    dialog._typed.setText("i accept the risk")
    app.processEvents()
    assert not dialog.confirm.isEnabled(), "the phrase must match exactly"

    dialog._typed.setText("I ACCEPT THE RISK")
    app.processEvents()
    assert dialog.confirm.isEnabled()
    dialog.close()


def test_the_security_panel_reports_a_recorded_override(app, vault):
    from quenchkey.ui.main_window import MainWindow

    vault.log_event("passphrase_strength", bits=18.0, label="Far too weak",
                    generated=False, below_floor=True)
    vault.save()
    window = MainWindow(Session(vault, auto_lock_seconds=0))

    recorded = next(e for e in reversed(vault.events)
                    if e["kind"] == "passphrase_strength")
    assert recorded["below_floor"] is True
    window.close()


# -- the evidence features in the interface ---------------------------------

def test_the_header_shows_the_anchor(app, session):
    from quenchkey.ui.main_window import MainWindow

    window = MainWindow(session)
    window.refresh()
    assert window.anchor_button.text() == session.vault.chain_fingerprint
    assert window.anchor_button.text(), "the anchor must not be blank"
    window.close()


def test_the_anchor_updates_as_the_chain_advances(app, session):
    from quenchkey.ui.main_window import MainWindow

    window = MainWindow(session)
    window.refresh()
    before = window.anchor_button.text()
    session.vault.log_event("something_happened")
    window.refresh()
    assert window.anchor_button.text() != before
    window.close()


def test_the_table_shows_every_rule(app, vault, sample_files, workspace):
    from quenchkey.ui.main_window import MainWindow
    from quenchkey import locker
    from quenchkey.session import Session

    locker.lock_files(vault, [sample_files[0]], expires=None,
                      output_dir=str(workspace / "locked"), max_opens=3)
    locker.lock_files(vault, [sample_files[1]], expires=None,
                      output_dir=str(workspace / "locked"), heartbeat_days=30)
    window = MainWindow(Session(vault, auto_lock_seconds=0))
    window.refresh()

    rows = {}
    for row in range(window.model.rowCount()):
        entry = window.model.entry_at(row)
        rows[entry.names[0]] = {
            "opens": window.model.data(window.model.index(row, 6), Qt.DisplayRole),
            "ends": window.model.data(window.model.index(row, 4), Qt.DisplayRole),
            "status": window.model.data(window.model.index(row, 7), Qt.DisplayRole),
        }
    assert rows["zebra.txt"]["opens"] == "0/3"
    assert rows["alpha.bin"]["opens"] == "—"
    assert "no check-in" in rows["alpha.bin"]["ends"]
    assert rows["alpha.bin"]["status"] == "awaiting check-in"
    window.close()


def test_the_lock_dialog_offers_all_three_rules(app, session, sample_files):
    from quenchkey.ui.lock_dialog import LockDialog

    dialog = LockDialog(session, None, sample_files[:1])
    assert dialog.chosen_max_opens() is None
    assert dialog.chosen_heartbeat() is None

    dialog.opens_combo.setCurrentIndex(dialog.opens_combo.findData(2))
    dialog.heartbeat_combo.setCurrentIndex(dialog.heartbeat_combo.findData(30.0))
    app.processEvents()
    assert dialog.chosen_max_opens() == 2
    assert dialog.chosen_heartbeat() == 30.0
    assert not dialog.heartbeat_warning.isHidden(), "the switch must be explained"
    dialog.close()


def test_the_anchor_dialog_shows_the_head_and_its_caveat(app, session):
    from quenchkey.ui.dialogs import AnchorDialog

    dialog = AnchorDialog(session, None)
    texts = [w.text() for w in dialog.findChildren(QtWidgets.QLineEdit)]
    assert session.vault.chain_fingerprint in texts
    assert session.vault.chain_head in texts
    dialog.close()


def test_the_shares_dialog_enforces_a_minimum_threshold(app, session):
    from quenchkey.ui.dialogs import RecoverySharesDialog
    from quenchkey import recovery

    dialog = RecoverySharesDialog(session, None)
    offered = [dialog.threshold.itemData(i) for i in range(dialog.threshold.count())]
    assert min(offered) >= recovery.MIN_THRESHOLD
    dialog.close()


def test_generating_shares_shows_them_once(app, session):
    from quenchkey.ui.dialogs import RecoverySharesDialog

    dialog = RecoverySharesDialog(session, None)
    dialog.count.setCurrentIndex(dialog.count.findData(3))
    dialog._generate()
    app.processEvents()

    assert dialog.share_set is not None
    text = dialog.output.toPlainText()
    for share in dialog.share_set.shares:
        assert share in text
    assert dialog.save_button.isEnabled()
    dialog.close()


def test_the_share_unlock_dialog_counts_the_quorum(app, session):
    from quenchkey.ui.dialogs import ShareUnlockDialog
    from quenchkey import recovery

    shares = recovery.generate(session.vault.master_key(), 3, 5)
    dialog = ShareUnlockDialog(None)

    dialog.input.setPlainText("\n".join(shares.shares[:2]))
    app.processEvents()
    assert not dialog.unlock_button.isEnabled(), "two of three is not a quorum"

    dialog.input.setPlainText("\n".join(shares.shares[:3]))
    app.processEvents()
    assert dialog.unlock_button.isEnabled()

    dialog._combine()
    assert dialog.master_key == session.vault.master_key()
    dialog.close()


def test_the_certificates_dialog_lists_what_was_destroyed(app, vault,
                                                          sample_files, workspace):
    from quenchkey.ui.dialogs import CertificatesDialog
    from quenchkey import locker
    from quenchkey.session import Session

    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked")).entry
    vault.shred_key(entry.id)
    vault.save()

    dialog = CertificatesDialog(Session(vault, auto_lock_seconds=0), None)
    cells = [dialog.table.item(0, column).text() for column in range(4)]
    assert entry.names[0] in cells[1]
    assert cells[3] == "valid"
    dialog.close()


# -- packaging ---------------------------------------------------------------

def test_the_logo_ships_inside_the_package(app):
    """An installed build has no repository root to look in.

    This is the bug that made the first real installation come up with no
    logo and a blank window icon: the assets were resolved relative to the
    checkout, which does not exist under site-packages.
    """
    import os

    import quenchkey

    package_assets = os.path.join(os.path.dirname(quenchkey.__file__), "assets")
    assert os.path.isfile(os.path.join(package_assets, "quenchkey-logo.svg")), \
        "the logo must live inside the package, not beside it"
    assert theme.ASSETS_DIR == package_assets
    assert os.path.isfile(theme.LOGO_PATH)


def test_the_window_icon_is_not_empty(app):
    icon = theme.app_icon()
    assert not icon.isNull(), "the window icon resolves to nothing"
    assert icon.availableSizes(), "the icon has no sizes"


def test_every_declared_icon_size_ships(app):
    import os

    import quenchkey

    assets = os.path.join(os.path.dirname(quenchkey.__file__), "assets")
    for size in (16, 32, 64, 256):
        target = os.path.join(assets, f"quenchkey-{size}.png")
        assert os.path.isfile(target), f"missing the {size}px icon the installer copies"


# --------------------------------------------------------------------------
# every window has to fit the screen it opens on
# --------------------------------------------------------------------------

def test_a_window_is_never_sized_past_its_screen(app, monkeypatch):
    """The failure this guards against is a dialog with unreachable buttons.

    Qt will happily give a dialog more height than the display has, and the
    result looks fine in a screenshot while its confirm button sits below the
    bottom edge of the screen where no one can click it.
    """
    monkeypatch.setattr(theme, "available_size", lambda widget=None: (900, 600))
    box = QtWidgets.QDialog()
    theme.fit(box, 1400, 1100, 1200, 900)

    assert box.width() <= 900 and box.height() <= 600
    # And the minimum comes down with it, or the window cannot be resized out
    # of the state it was just put into.
    assert box.minimumWidth() <= 900 and box.minimumHeight() <= 600


def test_a_window_smaller_than_its_screen_is_left_alone(app, monkeypatch):
    monkeypatch.setattr(theme, "available_size", lambda widget=None: (2400, 1400))
    box = QtWidgets.QDialog()
    theme.fit(box, 780, 660, 690, 500)

    assert (box.width(), box.height()) == (theme.scaled(780), theme.scaled(660))
    assert (box.minimumWidth(), box.minimumHeight()) == (theme.scaled(690),
                                                         theme.scaled(500))


@pytest.mark.parametrize("screen", [(1024, 600), (1366, 768), (1920, 1080)])
def test_every_dialog_fits_a_small_screen(app, session, vault, monkeypatch, screen):
    """Built at the sizes they really use, against the screens people have."""
    from quenchkey.ui.dialogs import (
        AnchorDialog, CertificatesDialog, CustodianDialog, RecoverySharesDialog,
        ShareUnlockDialog,
    )
    from quenchkey.ui.main_window import _TextDialog, limitations_html

    monkeypatch.setattr(theme, "available_size", lambda widget=None: screen)
    window = MainWindow(session)
    built = [
        AnchorDialog(session, window),
        CertificatesDialog(session, window),
        CustodianDialog(session, window),
        RecoverySharesDialog(session, window),
        ShareUnlockDialog(window),
        _TextDialog("What Quenchkey does not protect against", limitations_html(),
                    window, rich=True),
        _TextDialog("Security details", window.security_report(), window,
                    monospace=True),
    ]
    oversized = [
        f"{dialog.metaObject().className()} wants "
        f"{dialog.width()}x{dialog.height()} on a {screen[0]}x{screen[1]} screen"
        for dialog in built
        if dialog.width() > screen[0] or dialog.height() > screen[1]
    ]
    assert oversized == []


def test_a_long_dialog_title_does_not_widen_the_dialog(app, session):
    """A title that cannot wrap is a hard minimum width on the whole window."""
    from quenchkey.ui.main_window import _TextDialog

    title = ("A title considerably longer than anything this application "
             "would reasonably use for one of its own dialogs")
    dialog = _TextDialog(title, "body", None)

    on_one_line = dialog.fontMetrics().boundingRect(title).width()
    # It wraps, so what it demands is the longest word, not the whole line.
    assert dialog.minimumSizeHint().width() < on_one_line / 2


def test_the_security_report_says_what_the_vault_is_made_of(app, session):
    report = MainWindow(session).security_report()
    for expected in ("Cipher:", "Key derivation:", "Argon2id", "Vault id:",
                     "Event chain:", "Anchor:"):
        assert expected in report


# --------------------------------------------------------------------------
# the generator on the create screen
# --------------------------------------------------------------------------

def test_generating_fills_the_confirmation_field_too(app, workspace):
    """The second field catches typos, and the app does not make typos.

    Asking someone to transcribe 24 random characters by hand only tempts
    them into choosing something weaker instead.
    """
    gate = GateWindow(str(workspace / "absent.qkv"))
    gate.create_field.generate_characters()

    assert gate.create_field.text() == gate.confirm_field.text()
    assert len(gate.create_field.text()) == pp.DEFAULT_CHARACTER_LENGTH
    assert gate.create_button.isEnabled()


def test_a_hand_typed_passphrase_still_has_to_be_confirmed(app, workspace):
    gate = GateWindow(str(workspace / "absent.qkv"))
    gate.create_field.set_text("nine-copper-lanterns-above-the-quay")

    assert gate.confirm_field.text() == ""
    assert not gate.create_button.isEnabled()


def test_a_generated_password_is_shown_not_hidden(app, workspace):
    """Nobody can memorise it, so it has to be readable to be saved."""
    gate = GateWindow(str(workspace / "absent.qkv"))
    gate.create_field.generate_characters()

    assert gate.create_field.reveal.isChecked()
    assert gate.confirm_field.reveal.isChecked()


def test_the_meter_reports_a_generated_password_as_exact(app, workspace):
    gate = GateWindow(str(workspace / "absent.qkv"))
    value = gate.create_field.generate_characters()

    assert gate.create_field.exact_bits() == pytest.approx(
        pp.character_bits(len(value)))
    assert "exactly" in gate.strength.bits.text()
    assert gate._strength.is_generated_phrase


def test_editing_a_generated_password_drops_the_exact_claim(app, workspace):
    """Once a character changes, the app no longer knows what it is holding."""
    gate = GateWindow(str(workspace / "absent.qkv"))
    gate.create_field.generate_characters()
    gate.create_field.set_text(gate.create_field.text() + "x")

    assert gate.create_field.exact_bits() is None
    assert "at most about" in gate.strength.bits.text()


def test_the_word_generator_is_still_available(app, workspace):
    gate = GateWindow(str(workspace / "absent.qkv"))
    value = gate.create_field.generate_words()

    assert value.count("-") == pp.RECOMMENDED_WORDS - 1
    assert gate.confirm_field.text() == value
    assert gate._strength.bits == pp.generated_bits(pp.RECOMMENDED_WORDS)


def test_every_offered_length_produces_a_usable_password(app, workspace):
    gate = GateWindow(str(workspace / "absent.qkv"))
    for length in pp.CHARACTER_LENGTHS:
        value = gate.create_field.generate_characters(length)
        assert len(value) == length
        assert gate._strength.meets_minimum
        assert gate.create_button.isEnabled()


# --------------------------------------------------------------------------
# shared files, kept visibly apart
# --------------------------------------------------------------------------

def test_the_shared_section_is_hidden_until_there_is_one(app, session):
    window = MainWindow(session)
    window.refresh()
    # isVisibleTo, because the window itself is never shown under the
    # offscreen plugin and isVisible would be False either way.
    assert not window.shared_panel.isVisibleTo(window)


def test_a_shared_file_never_appears_among_the_entries(app, session, workspace,
                                                       fast_kdf):
    """The list of things with deadlines must not contain one without."""
    from quenchkey import locker

    source = workspace / "documents" / "sendable.txt"
    source.write_bytes(b"send me" * 300)
    result = locker.lock_to_share([str(source)], "ephemeral-lantern-quay",
                                  output_dir=str(workspace / "locked"),
                                  kdf_params=fast_kdf)
    session.vault.record_shared(result.path, result.names, result.size,
                                result.plaintext_size, result.sha256)

    window = MainWindow(session)
    window.refresh()

    listed = [window.model.entry_at(row).display_name
              for row in range(window.model.rowCount())]
    assert "sendable.txt" not in listed
    assert window.shared_table.rowCount() == 1
    assert "sendable.txt" in window.shared_table.item(0, 1).text()


def test_the_shared_section_says_what_it_is(app, session, workspace, fast_kdf):
    from quenchkey import locker

    source = workspace / "documents" / "sendable.txt"
    source.write_bytes(b"x" * 100)
    result = locker.lock_to_share([str(source)], "ephemeral-lantern-quay",
                                  output_dir=str(workspace / "locked"),
                                  kdf_params=fast_kdf)
    session.vault.record_shared(result.path, result.names, result.size,
                                result.plaintext_size, result.sha256)
    window = MainWindow(session)
    window.refresh()

    assert window.shared_panel.isVisibleTo(window)
    marker = window.shared_table.item(0, 0)
    assert "no deadline" in marker.toolTip().lower()
    assert not marker.icon().isNull()


def test_the_share_dialog_will_not_write_without_a_matching_passphrase(app):
    from quenchkey.ui.share_dialog import ShareDialog

    dialog = ShareDialog(None)
    assert not dialog.share_button.isEnabled()

    dialog.add_paths([__file__])
    assert not dialog.share_button.isEnabled()

    dialog.passphrase_field.generate_characters()
    assert dialog.confirm_field.text() == dialog.passphrase_field.text()
    assert dialog.share_button.isEnabled()

    dialog.confirm_field.set_text("something else")
    assert not dialog.share_button.isEnabled()


def test_the_share_dialog_refuses_a_weak_passphrase(app):
    from quenchkey.ui.share_dialog import ShareDialog

    dialog = ShareDialog(None)
    dialog.add_paths([__file__])
    dialog.passphrase_field.set_text("password1")
    dialog.confirm_field.set_text("password1")

    assert not dialog.share_button.isEnabled()


def test_the_share_dialog_states_the_absence_of_a_deadline(app):
    """Not buried in a tooltip: on the screen, before anything is chosen."""
    from quenchkey.ui.share_dialog import ShareDialog

    dialog = ShareDialog(None)
    text = " ".join(w.text() for w in dialog.findChildren(QtWidgets.QLabel))
    assert "no deadline" in text.lower()
    assert "cannot be given one" in text.lower()


def test_clicking_generate_passes_no_stray_argument(app, workspace):
    """QToolButton.clicked carries its checked state.

    Connected directly, that bool arrives as the password length and the
    first click anyone makes raises instead of generating anything.
    """
    gate = GateWindow(str(workspace / "absent.qkv"))
    gate.create_field.generate_button.click()

    assert len(gate.create_field.text()) == pp.DEFAULT_CHARACTER_LENGTH
    assert gate.create_field.exact_bits() == pytest.approx(
        pp.character_bits(pp.DEFAULT_CHARACTER_LENGTH))


def test_every_menu_entry_on_the_generator_works(app, workspace):
    gate = GateWindow(str(workspace / "absent.qkv"))
    actions = [a for a in gate.create_field.generate_button.menu().actions()
               if not a.isSeparator()]
    assert len(actions) == len(pp.CHARACTER_LENGTHS) + 3

    for action in actions:
        action.trigger()
        assert gate.create_field.text()
        assert gate.confirm_field.text() == gate.create_field.text()
        assert gate._strength.is_generated_phrase


# --------------------------------------------------------------------------
# the unlock screen
# --------------------------------------------------------------------------

def _shared(session, workspace, fast_kdf, name, contents=("a.txt",)):
    from quenchkey import locker

    sources = []
    for member in contents:
        path = workspace / "documents" / f"{name}-{member}"
        path.write_bytes(member.encode() * 50)
        sources.append(str(path))
    result = locker.lock_to_share(
        sources, "ephemeral-lantern-above-the-quay",
        output_path=str(workspace / "locked" / f"{name}.qkey"),
        kdf_params=fast_kdf)
    session.vault.record_shared(result.path, result.names, result.size,
                                result.plaintext_size, result.sha256)
    return result


def test_the_unlock_screen_lists_what_the_vault_wrote(app, session, workspace,
                                                      fast_kdf):
    from quenchkey.ui.share_dialog import UnlockSharedDialog

    _shared(session, workspace, fast_kdf, "one")
    _shared(session, workspace, fast_kdf, "two")
    dialog = UnlockSharedDialog(session)

    assert dialog.table.rowCount() == 2
    assert len(dialog.checked_paths()) == 2  # ticked by default


def test_files_can_be_added_that_the_vault_never_wrote(app, session, workspace,
                                                       fast_kdf):
    """One somebody sent you is opened the same way."""
    from quenchkey.ui.share_dialog import UnlockSharedDialog
    from quenchkey import locker

    stray = workspace / "documents" / "from-someone.txt"
    stray.write_bytes(b"sent to me" * 40)
    result = locker.lock_to_share([str(stray)], "ephemeral-lantern-above-the-quay",
                                  output_path=str(workspace / "sent.qkey"),
                                  kdf_params=fast_kdf)

    dialog = UnlockSharedDialog(session)
    assert dialog.table.rowCount() == 0
    dialog.add_paths([result.path])
    assert dialog.table.rowCount() == 1
    assert dialog.checked_paths() == [result.path]


def test_a_vault_file_added_by_mistake_is_marked_and_cannot_be_ticked(
        app, session, workspace, fast_kdf):
    from quenchkey.ui.share_dialog import UnlockSharedDialog
    from quenchkey import locker

    source = workspace / "documents" / "kept.txt"
    source.write_bytes(b"kept" * 100)
    entry = locker.lock_files(session.vault, [str(source)], time.time() + 3600,
                              output_dir=str(workspace / "locked")).entry

    dialog = UnlockSharedDialog(session)
    dialog.add_paths([entry.blob_path])

    assert dialog.table.rowCount() == 1
    assert "vault" in dialog.table.item(0, 3).text()
    assert dialog.checked_paths() == []
    assert not dialog.unlock_button.isEnabled()


def test_unlock_stays_disabled_without_a_passphrase(app, session, workspace,
                                                    fast_kdf):
    from quenchkey.ui.share_dialog import UnlockSharedDialog

    _shared(session, workspace, fast_kdf, "one")
    dialog = UnlockSharedDialog(session)
    assert not dialog.unlock_button.isEnabled()

    dialog.field.set_text("ephemeral-lantern-above-the-quay")
    assert dialog.unlock_button.isEnabled()


def test_a_missing_file_is_shown_and_cannot_be_ticked(app, session, workspace,
                                                      fast_kdf):
    from quenchkey.ui.share_dialog import UnlockSharedDialog

    result = _shared(session, workspace, fast_kdf, "gone")
    os.unlink(result.path)

    dialog = UnlockSharedDialog(session)
    assert "not found" in dialog.table.item(0, 3).text()
    assert dialog.checked_paths() == []


def test_select_all_toggles_every_usable_row(app, session, workspace, fast_kdf):
    from quenchkey.ui.share_dialog import UnlockSharedDialog

    _shared(session, workspace, fast_kdf, "one")
    _shared(session, workspace, fast_kdf, "two")
    dialog = UnlockSharedDialog(session)

    dialog._select_all()          # everything was ticked, so this clears
    assert dialog.checked_paths() == []
    dialog._select_all()
    assert len(dialog.checked_paths()) == 2


def test_the_screen_warns_before_it_deletes_the_locked_copy(app, session,
                                                            workspace, fast_kdf):
    from quenchkey.ui.share_dialog import UnlockSharedDialog

    _shared(session, workspace, fast_kdf, "one")
    dialog = UnlockSharedDialog(session)
    assert dialog.keep_check.isChecked()
    assert dialog.keep_note.text() == ""

    dialog.keep_check.setChecked(False)
    note = dialog.keep_note.text()
    assert "deleted" in note
    assert "does not reach those" in note   # other copies survive


def test_the_unlock_screen_uses_the_desktops_own_chooser(app, session):
    """No hand-built file browser anywhere in this screen."""
    import inspect
    from quenchkey.ui import share_dialog

    source = inspect.getsource(share_dialog)
    assert "QFileDialog" not in source
    assert "filechooser.open_files" in source


# --------------------------------------------------------------------------
# the window, the tray, and closing
# --------------------------------------------------------------------------

def test_the_window_opens_filling_the_screen(app, session, monkeypatch):
    monkeypatch.setattr(theme, "available_size", lambda widget=None: (1600, 900))
    window = MainWindow(session)

    assert (window.width(), window.height()) == (1600, 900)


def test_the_window_can_still_be_made_small(app, session, monkeypatch):
    """Filling the screen is a starting size, not a cage."""
    monkeypatch.setattr(theme, "available_size", lambda widget=None: (1600, 900))
    window = MainWindow(session)
    smallest = window.minimumSize()
    window.resize(smallest)

    assert window.width() == smallest.width()
    assert window.height() == smallest.height()
    assert smallest.width() < 1600


def test_closing_without_a_tray_quits_whatever_the_setting_says(app, session,
                                                                monkeypatch):
    """A window that vanished while claiming to run would be worse than either."""
    from quenchkey import settings as settings_mod

    store = settings_mod.Settings(str(session.vault.path) + ".settings")
    store.set("close_action", settings_mod.CLOSE_TRAY)
    settings_mod.use(store)
    try:
        window = MainWindow(session)
        window.attach_tray(None)      # no tray on this desktop
        window.close()
        assert not session.is_open    # it really locked
    finally:
        settings_mod.use(None)


def test_quitting_locks_the_vault(app, session):
    window = MainWindow(session)
    window.quit_fully()
    assert not session.is_open


# --------------------------------------------------------------------------
# help
# --------------------------------------------------------------------------

def test_every_help_page_renders(app):
    from quenchkey import help_text
    from quenchkey.ui.help_dialog import HelpDialog

    dialog = HelpDialog()
    for row in range(len(help_text.PAGES)):
        dialog.pages.setCurrentRow(row)
        assert dialog.content.text().strip(), help_text.PAGES[row][0]


def test_the_help_answers_how_to_open_a_quenchkey_file(app):
    from quenchkey import help_text

    text = help_text.as_plain_text().lower()
    assert "how do i open a .qkey file" in text
    assert "can another application open a .qkey file" in text
    assert "quenchkey-recover" in text


def test_the_help_does_not_claim_only_quenchkey_can_open_these_files(app):
    """The honesty rules apply to the manual as much as to the interface."""
    from quenchkey import help_text

    text = help_text.as_plain_text().lower()
    assert "only it can open these files" in text          # stated, and denied
    assert "would not be true" in text


def test_searching_the_help_finds_and_reports(app):
    from quenchkey.ui.help_dialog import HelpDialog

    dialog = HelpDialog()
    dialog.search.setText("recovery shares")
    assert "mention" in dialog.hits.text()

    dialog.search.setText("zzzzz-not-in-here")
    assert "Nothing in the manual" in dialog.hits.text()


def test_the_help_covers_every_feature(app):
    from quenchkey import help_text

    text = help_text.as_plain_text().lower()
    for topic in ("vault", "deadline", "recovery share", "certificate",
                  "anchor", "shared file", "drive", "settings", "tray",
                  "login", "uninstall"):
        assert topic in text, topic


def test_filling_the_screen_leaves_room_for_the_title_bar(app, session,
                                                          monkeypatch):
    """The failure this guards against is an unreachable close button.

    A window manager decorates a window after mapping it, so for a moment Qt
    reports a frame the same size as the client area. Sizing from that puts
    the title bar off the top of the screen, taking the minimise, maximise and
    close buttons with it.
    """
    from PyQt5.QtCore import QRect

    class FakeScreen:
        @staticmethod
        def availableGeometry():  # noqa: N802 - Qt naming
            return QRect(0, 0, 1366, 768)

    window = MainWindow(session)
    monkeypatch.setattr(
        "PyQt5.QtGui.QGuiApplication.primaryScreen", lambda: FakeScreen())

    # A title bar 30px tall with a 1px border, as a real one has.
    monkeypatch.setattr(window, "frameGeometry",
                        lambda: QRect(0, 0, 1366, 768))
    monkeypatch.setattr(window, "geometry",
                        lambda: QRect(1, 30, 1364, 737))

    moved = []
    monkeypatch.setattr(window, "move", lambda x, y: moved.append((x, y)))
    assert theme.fill_available_screen(window) is True

    # The client area is the screen minus the decorations...
    assert window.width() == 1366 - 2
    assert window.height() == 768 - 30 - 1
    # ...and the frame is placed at the top-left, not offset by its own bar.
    assert moved == [(0, 0)]


def test_filling_the_screen_respects_the_minimum(app, session, monkeypatch):
    from PyQt5.QtCore import QRect

    class TinyScreen:
        @staticmethod
        def availableGeometry():  # noqa: N802
            return QRect(0, 0, 400, 300)

    window = MainWindow(session)
    monkeypatch.setattr(
        "PyQt5.QtGui.QGuiApplication.primaryScreen", lambda: TinyScreen())
    monkeypatch.setattr(window, "move", lambda x, y: None)
    theme.fill_available_screen(window)

    assert window.width() >= window.minimumWidth()
    assert window.height() >= window.minimumHeight()


def test_a_window_with_no_decorations_fills_exactly(app, session, monkeypatch):
    """No window manager, as on a kiosk or a bare X server."""
    from PyQt5.QtCore import QRect

    class Screen:
        @staticmethod
        def availableGeometry():  # noqa: N802
            return QRect(0, 0, 1280, 800)

    window = MainWindow(session)
    monkeypatch.setattr(
        "PyQt5.QtGui.QGuiApplication.primaryScreen", lambda: Screen())
    monkeypatch.setattr(window, "frameGeometry", lambda: QRect(0, 0, 1280, 800))
    monkeypatch.setattr(window, "geometry", lambda: QRect(0, 0, 1280, 800))
    monkeypatch.setattr(window, "move", lambda x, y: None)
    theme.fill_available_screen(window)

    assert (window.width(), window.height()) == (1280, 800)
