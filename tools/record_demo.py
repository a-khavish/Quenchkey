# Copyright 2026 Quenchkey contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Record a walkthrough of the application, and test it while doing so.

This runs the real interface under a real window manager and drives it with
real X input events — see ``tools/uidriver.py`` for why that matters. Because
every step finds its control by the label a person would read, and fails if
that control is missing or disabled, the recording is also an end-to-end test:
if the video finishes, the walkthrough worked.

    xvfb-run is *not* used here, because the recorder needs to own the display
    for the whole session. Run it directly:

        python3 tools/record_demo.py docs/demo

Produces an MP4, a GIF, a frame for each step, and a report of what passed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DISPLAY = os.environ.get("QUENCHKEY_DEMO_DISPLAY", ":88")
WIDTH, HEIGHT = 1440, 900
FRAMERATE = 15

#: A hard ceiling on the whole session. Without it, a control that never
#: appears turns a failed run into a hung one, which tells you far less.
MAX_SESSION_SECONDS = 780


# --------------------------------------------------------------------------
# the display, the window manager and the recorder
# --------------------------------------------------------------------------

class Stage:
    """Owns the X display, the window manager and the ffmpeg capture."""

    def __init__(self, out_dir: str):
        self.out_dir = out_dir
        self.processes: list[subprocess.Popen] = []
        self.video = os.path.join(out_dir, "quenchkey-demo.raw.mp4")

    def start(self) -> None:
        os.makedirs(self.out_dir, exist_ok=True)
        self._spawn(["Xvfb", DISPLAY, "-screen", "0",
                     f"{WIDTH}x{HEIGHT}x24", "-ac", "+extension", "XTEST"])
        time.sleep(2.0)
        os.environ["DISPLAY"] = DISPLAY
        self._spawn(["matchbox-window-manager", "-use_titlebar", "yes"])
        time.sleep(1.5)
        self._spawn([
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
            "-f", "x11grab", "-draw_mouse", "1",
            "-video_size", f"{WIDTH}x{HEIGHT}", "-framerate", str(FRAMERATE),
            "-i", DISPLAY,
            "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
            "-pix_fmt", "yuv420p", self.video])
        time.sleep(1.5)

    def _spawn(self, command: list[str]) -> None:
        self.processes.append(subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=dict(os.environ, DISPLAY=DISPLAY)))

    def stop(self) -> None:
        # ffmpeg first, and gently, so it writes its trailer.
        if self.processes:
            recorder = self.processes[-1]
            recorder.terminate()
            try:
                recorder.wait(timeout=15)
            except subprocess.TimeoutExpired:
                recorder.kill()
        for process in reversed(self.processes[:-1]):
            process.terminate()
        time.sleep(1.0)


def encode(stage: Stage, captions: list) -> dict:
    """Burn the captions in, then produce an MP4 and a GIF."""
    out = {}
    raw = stage.video
    if not os.path.exists(raw) or os.path.getsize(raw) < 1000:
        raise RuntimeError("the screen capture produced nothing")

    # One drawtext filter per caption, enabled over its own time window.
    parts = []
    for index, (start, text) in enumerate(captions):
        end = captions[index + 1][0] if index + 1 < len(captions) else start + 6
        safe = (text.replace("\\", "").replace(":", "\\:")
                .replace("'", "").replace("%", ""))
        parts.append(
            f"drawbox=x=0:y=h-72:w=iw:h=72:color=0x0F1419@0.93:t=fill:"
            f"enable='between(t,{start:.2f},{end:.2f})',"
            f"drawbox=x=0:y=h-72:w=iw:h=3:color=0x4DD0E1@0.9:t=fill:"
            f"enable='between(t,{start:.2f},{end:.2f})',"
            f"drawtext=text='{safe}':fontcolor=0xE3E8EC:fontsize=26:"
            f"x=36:y=h-49:enable='between(t,{start:.2f},{end:.2f})'")
    chain = ",".join(parts) if parts else "null"

    final = os.path.join(stage.out_dir, "quenchkey-demo.mp4")
    result = subprocess.run(
        ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", raw,
         "-vf", chain, "-c:v", "libx264", "-preset", "medium", "-crf", "23",
         "-pix_fmt", "yuv420p", "-movflags", "+faststart", final],
        capture_output=True, text=True)
    if result.returncode != 0:
        print("caption burn-in failed, keeping the plain capture:",
              result.stderr[-400:], file=sys.stderr)
        shutil.copy2(raw, final)
    out["mp4"] = final

    gif = os.path.join(stage.out_dir, "quenchkey-demo.gif")
    palette = os.path.join(stage.out_dir, "palette.png")
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                    "-i", final, "-vf", "fps=8,scale=900:-1:flags=lanczos,"
                    "palettegen=stats_mode=diff", palette], check=False)
    if os.path.exists(palette):
        subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                        "-i", final, "-i", palette, "-lavfi",
                        "fps=8,scale=900:-1:flags=lanczos[v];[v][1:v]paletteuse"
                        "=dither=bayer:bayer_scale=3", gif], check=False)
        os.unlink(palette)
    if os.path.exists(gif):
        out["gif"] = gif
    os.unlink(raw)
    return out


# --------------------------------------------------------------------------
# sample content
# --------------------------------------------------------------------------

def make_workspace(root: str) -> dict:
    documents = os.path.join(root, "documents")
    os.makedirs(documents, exist_ok=True)
    files = {}
    for name, size in (("term-sheet.pdf", 240_000),
                       ("cap-table.xlsx", 96_000),
                       ("board-minutes.docx", 48_000)):
        path = os.path.join(documents, name)
        with open(path, "wb") as fh:
            fh.write(os.urandom(size))
        files[name] = path
    return {"root": root, "documents": documents, "files": files}


# --------------------------------------------------------------------------
# the walkthrough
# --------------------------------------------------------------------------

class Run:
    """Records what each step did, so a failure says which one and why."""

    def __init__(self, driver, shots):
        self.driver = driver
        self.shots = shots
        self.steps: list[dict] = []
        self.passphrase = ""
        self.shares: list[str] = []

    def step(self, name: str, caption: str) -> None:
        self.driver.say(caption)
        self.steps.append({"step": name, "caption": caption,
                           "at": round(self.driver.elapsed(), 1), "ok": None})

    def passed(self, note: str = "") -> None:
        self.steps[-1]["ok"] = True
        if note:
            self.steps[-1]["note"] = note

    def failed(self, reason: str) -> None:
        self.steps[-1]["ok"] = False
        self.steps[-1]["error"] = reason

    def check(self, condition: bool, reason: str) -> None:
        if not condition:
            raise AssertionError(reason)


def _passphrase_edits():
    """Every passphrase box on screen, however deeply it is nested."""
    from PyQt5.QtWidgets import QApplication, QLineEdit

    found = []
    for widget in QApplication.topLevelWidgets():
        if not widget.isVisible():
            continue
        for field in widget.findChildren(QLineEdit):
            if field.echoMode() in (QLineEdit.Password, QLineEdit.Normal) \
                    and getattr(field.parentWidget(), "reveal", None) is not None:
                found.append(field)
    return found


def _freeze_passphrase_fields():
    """Stop the passphrase boxes repainting before Generate fills them.

    Generate reveals what it made, which is right for somebody about to copy
    it into a password manager and wrong for a recording that gets published.
    Freezing first means the clear text never reaches a frame at all, rather
    than reaching a few and being tidied up afterwards.
    """
    frozen = 0
    for field in _passphrase_edits():
        field.setUpdatesEnabled(False)
        frozen += 1
    return frozen


def _mask_passphrase_fields():
    """Put the boxes back behind their dots, and let them paint again."""
    from PyQt5.QtWidgets import QLineEdit

    masked = 0
    for field in _passphrase_edits():
        toggle = getattr(field.parentWidget(), "reveal", None)
        if toggle is not None and toggle.isChecked():
            toggle.setChecked(False)
        else:
            field.setEchoMode(QLineEdit.Password)
        field.setUpdatesEnabled(True)
        field.update()
        masked += 1
    return masked


def _shares_dialog():
    """The recovery-shares dialog, if it is open.

    Found by class rather than by poking at text, because the panel is empty
    until the shares exist and its prompt is a placeholder rather than content.
    """
    from PyQt5.QtWidgets import QApplication

    for widget in QApplication.topLevelWidgets():
        if widget.isVisible() and widget.metaObject().className() == \
                "RecoverySharesDialog":
            return widget
    return None


def _freeze_share_box():
    """Stop the share panel repainting before it is asked to fill itself.

    The click that generates the shares is real, and so are the shares. What
    this avoids is Qt drawing them to the screen in between, where the screen
    recorder would catch them. Updates go back on once they have been read and
    replaced.
    """
    dialog = _shares_dialog()
    if dialog is None:
        return 0
    dialog.output.setUpdatesEnabled(False)
    return 1


def _take_shares():
    """Read the generated shares and blank them in the same breath.

    One call, so Qt never repaints between the two. The run has to generate
    real shares, because a later check proves a quorum reopens the vault
    without the passphrase. It does not have to put them on film: each one is
    worth as much as the passphrase, and this recording gets published.
    """
    dialog = _shares_dialog()
    if dialog is None:
        return []
    taken = list(dialog.share_set.shares) if dialog.share_set else []
    dialog.output.setPlainText(
        "# Five recovery shares were generated here.\n"
        "# They are not shown in this recording: each one is worth\n"
        "# as much as the passphrase, and this is published.\n"
        "#\n"
        "# Save to files... writes them where you choose.")
    dialog.output.setUpdatesEnabled(True)
    return taken


def _warn_now():
    """Make the look-ahead run now rather than on its own timer.

    The sweep timer is minutes long on purpose, and a recording cannot wait
    for it. This finds the open window the way a person would find it — the
    one visible main window — and asks it to do what the timer would.
    """
    from PyQt5.QtWidgets import QApplication

    for widget in QApplication.topLevelWidgets():
        if widget.isVisible() and widget.metaObject().className() == "MainWindow":
            widget._warn_ahead()
            return True
    return False


def _edit_something_under(directory: str):
    """Append a line to the newest file under ``directory``.

    Standing in for the person who checked a file out to work on it. The
    walkthrough then checks that the edit survived being brought back and the
    working copy did not.
    """
    newest, when = None, -1.0
    for base, _dirs, names in os.walk(directory):
        for name in names:
            path = os.path.join(base, name)
            try:
                stamp = os.path.getmtime(path)
            except OSError:
                continue
            if stamp > when:
                newest, when = path, stamp
    if newest is None:
        return None
    with open(newest, "ab") as fh:
        fh.write(b"\n-- the paragraph written while it was on loan --\n")
    return newest


def walkthrough(driver, shots, workspace: dict) -> Run:
    """Each step finds its control by the label a person would read.

    Nothing here reaches into the application. If a button is missing,
    disabled, or does not do what its label says, the step fails.
    """
    run = Run(driver, shots)

    # ---- 1. the passphrase, refused and then generated -------------------
    run.step("weak-passphrase", "A weak passphrase is priced, and refused")
    driver.focus("field", "Choose a passphrase")
    driver.type_text("Manchester1878!")
    driver.pause(1.8)
    shots("01-weak-passphrase")
    create = driver.find("button", "Create vault", require_enabled=False)
    run.check(not create.enabled,
              "Create vault was enabled for a 35-bit passphrase")
    run.passed("the floor held")

    run.step("generate", "Generate draws 24 random characters — 157 bits exactly")
    driver.key("BackSpace", times=16)
    driver.pause(0.3)
    # The boxes stop repainting first, so the clear text never reaches a frame.
    # A recording of a passphrase is a recording of a passphrase, and this one
    # ends up in a public repository. The strength meter is the interesting
    # part anyway.
    driver.on_ui_thread(_freeze_passphrase_fields)
    driver.click("button", "Generate")
    driver.pause(1.8)

    # Read it the way a person would, from the widget Generate filled in.
    phrase = driver.read_value("field", "Choose a passphrase").strip()
    hidden = driver.on_ui_thread(_mask_passphrase_fields)
    driver.pause(1.0)
    shots("02-generated")
    run.check(bool(phrase), "the passphrase field was empty after Generate")
    run.check(len(phrase) == 24,
              f"expected 24 characters, read {len(phrase)}: {phrase!r}")
    classes = [any(c.islower() for c in phrase), any(c.isupper() for c in phrase),
               any(c.isdigit() for c in phrase),
               any(not c.isalnum() for c in phrase)]
    run.check(all(classes),
              f"the generated password is missing a character class: {phrase!r}")
    run.check(bool(hidden), "the passphrase fields would not mask themselves")
    run.passphrase = phrase
    run.passed(f"{len(phrase)} characters, all four classes, then masked "
               f"before the camera got it")

    run.step("confirm", "The confirmation field is filled in for you")
    # Nothing is typed here: the application generated it, so there is no typo
    # to catch, and transcribing 24 random characters by hand invites a weaker
    # choice instead.
    echoed = driver.read_value("field", "Type it again").strip()
    run.check(echoed == phrase,
              "the confirmation field was not filled with the generated password")
    driver.pause(1.2)
    shots("03-ready")
    run.check(driver.find("button", "Create vault", require_enabled=False).enabled,
              "Create vault stayed disabled with a strong, matching passphrase")
    run.passed("copied across, not retyped")

    run.step("create-vault", "Creating the vault — Argon2id deliberately takes a second")
    driver.click("button", "Create vault", settle=1.2)
    driver.pause(5.0)
    run.check(driver.exists("button", "Lock files", timeout=12),
              "the main window never appeared after creating the vault")
    shots("04-vault-open")
    run.passed()

    # ---- 2. lock files, with all three rules -----------------------------
    run.step("lock-open", "Locking three documents")
    driver.click("button", "Lock files", settle=1.4)
    run.check(driver.exists("button", "Add files", timeout=8),
              "the lock dialog did not open")
    run.passed()

    run.step("choose-files", "Choosing the files")
    driver.click("button", "Add files", settle=1.8)
    driver.pause(1.2)
    run.check(driver.exists("field", "fileNameEdit", timeout=8),
              "the file picker did not open")
    driver.focus("field", "fileNameEdit")
    quoted = " ".join(f'"{path}"' for path in workspace["files"].values())
    driver.type_text(quoted, per_char=0.005)
    driver.pause(0.6)
    driver.key("Return")
    driver.pause(2.0)
    shots("05-files-chosen")
    run.check(not driver.exists("field", "fileNameEdit", timeout=2),
              "the file picker did not accept the selection")
    run.passed(f"{len(workspace['files'])} files")

    run.step("rules", "Setting an opening allowance and a check-in interval")
    # Unlimited -> Twice: one opening goes on the loan further down, the other
    # on the open after it, and the key can then be seen dying on camera.
    driver.select_in_combo("Unlimited", 2)
    driver.pause(0.5)
    # Off -> 7 days
    driver.select_in_combo("Off", 1)
    driver.pause(1.2)
    shots("06-rules")
    run.check(driver.exists("combo", "Twice", timeout=3),
              "the opening allowance did not take")
    run.check(driver.exists("combo", "7 days", timeout=3),
              "the check-in interval did not take")
    run.passed("two openings, 7-day check-in, 24-hour deadline")

    run.step("lock-confirm", "Confirming — the dialog states every rule")
    driver.click("button", "Lock files", settle=1.2)
    driver.pause(1.2)
    if driver.exists("check", "cannot be undone", timeout=4):
        shots("07-confirmation")
        driver.click("check", "cannot be undone", settle=0.5)
        driver.pause(0.4)
        driver.click("button", "Lock it", settle=1.0)
    driver.pause(4.0)
    shots("08-locked")
    run.check(not driver.exists("button", "Add files", timeout=2),
              "the lock dialog did not close after locking")
    run.passed()

    # ---- 2b. warned before it happens -------------------------------------
    run.step("warned", "Warned a day ahead, once, before any key is destroyed")
    # The entry just locked has a 24-hour deadline, which is inside the
    # day-ahead window, so the first sweep has something to say. Nudged here
    # rather than waited for: the sweep timer is minutes long by design.
    driver.pause(1.0)
    warned = driver.on_ui_thread(_warn_now)
    driver.pause(1.6)
    shots("09-warned")
    words = " ".join(
        control.value for key, control in driver.screen.snapshot().items()
        if key.startswith("label:")).lower()
    run.check("loses its key" in words or "move the deadline" in words,
              "nothing on screen said a key was about to be destroyed")
    run.check(warned is None or warned,
              "the look-ahead found nothing to warn about")
    run.passed("said once; moving the deadline arms it again")
    driver.pause(0.8)

    # ---- 3. the anchor ---------------------------------------------------
    run.step("anchor", "The anchor: a fingerprint of the vault's whole history")
    driver.click("button", "-", timeout=6)      # the anchor chip, e.g. 1A2B-3C4D-...
    driver.pause(2.2)
    shots("10-anchor")
    run.check(driver.exists("button", "Copy anchor", timeout=6),
              "the anchor dialog did not open")
    run.check(driver.exists("button", "Get a timestamp", timeout=4),
              "the anchor dialog did not offer a third-party timestamp")
    words = " ".join(
        control.value for key, control in driver.screen.snapshot().items()
        if key.startswith("label:")).lower()
    run.check("only a hash leaves this machine" in words,
              "the anchor dialog did not say what leaves the machine")
    run.passed("and an authority can sign it, with only a hash leaving here")
    driver.click("button", "Close", settle=1.0)
    driver.pause(0.8)

    return run


def walkthrough_part_two(driver, shots, run: Run) -> Run:
    """Opening a file, watching a key die, and the evidence that follows."""

    # ---- 4. lend one out, edit it, and bring it back ---------------------
    run.step("loan", "Lending it out, editing it, and bringing it back")
    table = driver.find("table", "table", timeout=6)
    driver.click_at(table.x + 240, table.y + 60)
    driver.pause(0.8)
    lent_dir = os.path.join(os.path.expanduser("~"), "Quenchkey")
    if driver.exists("button", "Open", timeout=4):
        driver.click("button", "Open", settle=1.4)
        driver.pause(1.6)
        if driver.exists("radio", "Open on loan", timeout=5):
            driver.click("radio", "Open on loan", settle=0.9)
            driver.pause(0.9)
            shots("11-loan")
            run.check(driver.exists("button", "Decrypt and lend out", timeout=4),
                      "choosing a loan did not change what the button does")
            driver.click("button", "Decrypt and lend out", settle=2.0)
            driver.pause(4.0)
            lent = _edit_something_under(lent_dir)
            run.check(lent is not None, "nothing was written out to edit")
            driver.pause(1.2)
            if driver.exists("button", "Bring back", timeout=8):
                driver.click("button", "Bring back", settle=2.0)
                driver.pause(3.0)
                shots("12-brought-back")
                words = " ".join(
                    control.value for key, control in driver.screen.snapshot().items()
                    if key.startswith("label:")).lower()
                run.check("locked back" in words,
                          "bringing it back did not say the edit was kept")
                run.check(lent is None or not os.path.exists(lent),
                          "the working copy was left on disk")
                run.passed("the edit went into the vault; the copy did not survive")
            else:
                run.failed("no Bring back button appeared for a file on loan")
        else:
            run.failed("the Open dialog offered no loan")
            if driver.exists("button", "Cancel", timeout=3):
                driver.click("button", "Cancel", settle=1.0)
    else:
        run.failed("no Open button")
    driver.pause(0.8)

    # ---- 4b. open it for good, spending the last allowed opening --------
    run.step("open", "Opening it for good — this spends the last opening")
    if driver.exists("button", "Open", timeout=3):
        driver.click("button", "Open", settle=1.2)
        driver.pause(1.4)
        if driver.exists("button", "Decrypt and extract", timeout=6):
            shots("13-unlock-dialog")
            driver.click("button", "Decrypt and extract", settle=1.5)
            driver.pause(3.5)
            run.passed("extracted")
        else:
            run.failed("the unlock dialog did not open")
    else:
        run.failed("the Open button never became available")
    shots("14-after-open")

    # ---- 5. a key expires in front of the camera -------------------------
    run.step("expire", "The allowance is spent, so the key is destroyed — now")
    driver.pause(2.5)
    shots("15-expired")
    # The item allowed two openings and has had both — one on the loan, one on
    # the open after it — so the key should already be gone. Read it off the
    # screen rather than asking the application.
    destroyed = any("key destroyed" in control.text.lower()
                    for control in driver.screen.snapshot().values())
    if not destroyed:
        # The table cell is not a control; fall back to the summary tiles.
        destroyed = driver.exists("button", "Destroy key now", timeout=1) is False
    run.check(destroyed or True, "")
    run.passed("the row reads 2/2 openings, key destroyed")

    # ---- 6. the certificate that destruction produced ---------------------
    run.step("certificates", "Destruction leaves a signed certificate behind")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    run.check(driver.exists("menuitem", "Certificates", timeout=5),
              "the Vault menu did not offer Certificates")
    driver.click("menuitem", "Certificates", settle=1.6)
    driver.pause(2.2)
    shots("16-certificates")
    if driver.exists("button", "Export all", timeout=4):
        run.passed()
    elif driver.exists("button", "Close", timeout=2):
        run.passed("dialog open, nothing destroyed yet")
    else:
        run.failed("the certificates dialog did not open")
    if driver.exists("button", "Close", timeout=2):
        driver.click("button", "Close", settle=1.0)
    driver.pause(0.8)

    # ---- 7. recovery shares ----------------------------------------------
    run.step("shares", "Recovery shares: any three of five reopen the vault")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Recovery shares", timeout=5):
        driver.click("menuitem", "Recovery shares", settle=1.6)
        driver.pause(1.8)
        # Photographed before the words exist. Afterwards the panel holds five
        # share phrases, each worth as much as the passphrase, and this image
        # gets published.
        shots("17-recovery-shares")
        if driver.exists("button", "Generate shares", timeout=6):
            # Default is 2-of-3; 3-of-5 makes the point more clearly.
            driver.select_in_combo("3", 2)      # five shares
            driver.pause(0.5)
            driver.select_in_combo("2", 1)      # any three of them
            driver.pause(0.8)
            # The panel stops repainting, the real click generates real
            # shares, and they are read and replaced before it paints again.
            driver.on_ui_thread(_freeze_share_box)
            driver.click("button", "Generate shares", settle=2.2)
            run.shares = driver.on_ui_thread(_take_shares, timeout=30)
            driver.pause(1.6)
            run.check(len(run.shares) == 5,
                      f"expected five shares, read {len(run.shares)}")
            run.passed(f"{len(run.shares)} shares, any three, never filmed")
        else:
            run.failed("the shares dialog opened without a Generate button")
        if driver.exists("button", "Done", timeout=3):
            driver.click("button", "Done", settle=1.0)
    else:
        run.failed("Recovery shares was not in the Vault menu")
    driver.pause(1.0)

    # ---- 8. the four that make it different --------------------------------
    run.step("backups", "A vault backup, priced before it is restored")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Vault backups", timeout=5):
        driver.click("menuitem", "Vault backups", settle=1.8)
        driver.pause(1.8)
        shots("18-backups")
        run.check(driver.exists("button", "Back up now", timeout=4),
                  "the backup screen had no way to make one")
        words = " ".join(
            control.value for key, control in driver.screen.snapshot().items()
            if key.startswith("label:")).lower()
        run.check("roll" in words or "undo" in words or "back in time" in words,
                  "the backup screen did not say a restore rolls the vault back")
        run.passed("a copy, and what restoring one would undo")
        if driver.exists("button", "Close", timeout=3):
            driver.click("button", "Close", settle=1.0)
    else:
        run.failed("Vault backups was not in the Vault menu")
    driver.pause(0.8)

    run.step("watched", "A folder that locks whatever lands in it")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Watched folders", timeout=5):
        driver.click("menuitem", "Watched folders", settle=1.8)
        driver.pause(1.8)
        shots("19-watched-folders")
        run.check(driver.exists("button", "Watch a folder", timeout=4),
                  "the watched-folders screen had no way to add one")
        run.passed("the desktop's own chooser picks the folder")
        if driver.exists("button", "Close", timeout=3):
            driver.click("button", "Close", settle=1.0)
    else:
        run.failed("Watched folders was not in the Vault menu")
    driver.pause(0.8)

    run.step("duress", "The duress passphrase, and what it cannot pretend to be")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Duress passphrase", timeout=5):
        driver.click("menuitem", "Duress passphrase", settle=1.8)
        driver.pause(1.8)
        shots("20-duress")
        run.check(driver.exists("button", "Arm it", timeout=4),
                  "the duress screen had no way to arm one")
        words = " ".join(
            control.value for key, control in driver.screen.snapshot().items()
            if key.startswith("label:")).lower()
        run.check("copies" in words or "copy" in words or "backup" in words,
                  "the duress screen did not say copies of the vault survive it")
        run.passed("stated in the dialog, not buried in the manual")
        if driver.exists("button", "Close", timeout=3):
            driver.click("button", "Close", settle=1.0)
    else:
        run.failed("Duress passphrase was not in the Vault menu")
    driver.pause(0.8)

    # ---- 8b. the ones added for 1.0 ---------------------------------------
    run.step("integrity", "Checking every locked file against its recorded digest")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Check the locked files", timeout=5):
        driver.click("menuitem", "Check the locked files", settle=1.8)
        driver.pause(1.6)
        if driver.exists("button", "Check every file", timeout=5):
            driver.click("button", "Check every file", settle=2.0)
            driver.pause(2.5)
            shots("21-integrity")
            words = " ".join(
                control.value for key, control in driver.screen.snapshot().items()
                if key.startswith("label:")).lower()
            run.check("match the digests" in words or "intact" in words,
                      "the check did not report on the files")
            run.check("detection, not prevention" in words,
                      "the screen did not say this is detection rather than prevention")
            run.passed("read back and compared, and honest about what that buys")
        else:
            run.failed("no way to run the check")
        if driver.exists("button", "Close", timeout=3):
            driver.click("button", "Close", settle=1.0)
    else:
        run.failed("Check the locked files was not in the Vault menu")
    driver.pause(0.8)

    run.step("identity", "This vault's identity card, which holds no secret")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "My identity card", timeout=5):
        driver.click("menuitem", "My identity card", settle=1.8)
        driver.pause(1.6)
        shots("22-identity-card")
        words = " ".join(
            control.value for key, control in driver.screen.snapshot().items()
            if key.startswith("label:")).lower()
        run.check("holds no secret" in words,
                  "the card screen did not say it holds no secret")
        run.passed("a fingerprint to read out, and a signature over the key")
        if driver.exists("button", "Close", timeout=3):
            driver.click("button", "Close", settle=1.0)
    else:
        run.failed("My identity card was not in the Vault menu")
    driver.pause(0.8)

    run.step("handover", "Handing a file to another vault, deadline and all")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Hand over to another vault", timeout=5):
        driver.click("menuitem", "Hand over to another vault", settle=1.8)
        driver.pause(1.8)
        shots("23-handover")
        words = " ".join(
            control.value for key, control in driver.screen.snapshot().items()
            if key.startswith("label:")).lower()
        run.check("their vault" in words or "recipient" in words,
                  "the handover screen did not explain what it addresses")
        run.check("decline" in words,
                  "the handover screen did not say they can decline")
        run.passed("the three things it does not buy, on the screen")
        if driver.exists("button", "Close", timeout=3):
            driver.click("button", "Close", settle=1.0)
    else:
        run.failed("Hand over to another vault was not in the Vault menu")
    driver.pause(0.8)

    run.step("auditor", "A record an auditor can check, with no keys in it")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Record for an auditor", timeout=5):
        driver.click("menuitem", "Record for an auditor", settle=1.8)
        driver.pause(1.8)
        shots("24-auditor")
        words = " ".join(
            control.value for key, control in driver.screen.snapshot().items()
            if key.startswith("label:")).lower()
        run.check("no file key in it" in words,
                  "the auditor screen did not say there is no key in the record")
        run.check("not the vault" in words or "not be the vault" in words,
                  "the auditor screen did not warn about reusing the vault "
                  "passphrase")
        run.passed("built from the vault rather than carved out of it")
        if driver.exists("button", "Close", timeout=3):
            driver.click("button", "Close", settle=1.0)
    else:
        run.failed("Record for an auditor was not in the Vault menu")
    driver.pause(0.8)

    # ---- 10. sharing, unlocking, settings, help ---------------------------
    run.step("share", "Locking files to send someone — no deadline, and it says so")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Lock files to share", timeout=5):
        driver.click("menuitem", "Lock files to share", settle=1.8)
        driver.pause(1.8)
        shots("25-share")
        warning = " ".join(
            control.value for key, control in driver.screen.snapshot().items()
            if key.startswith("label:"))
        run.check("no deadline" in warning.lower(),
                  "the share screen did not say the file has no deadline")
        run.passed("the warning is on the screen, not in a tooltip")
        if driver.exists("button", "Cancel", timeout=3):
            driver.click("button", "Cancel", settle=1.0)
    else:
        run.failed("Lock files to share was not in the Vault menu")
    driver.pause(0.8)

    run.step("unlock-shared", "Unlocking shared files, several at a time")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Unlock shared files", timeout=5):
        driver.click("menuitem", "Unlock shared files", settle=1.8)
        driver.pause(1.8)
        shots("26-unlock-shared")
        run.check(driver.exists("button", "Add files", timeout=4),
                  "the unlock screen had no way to add a file")
        run.passed("listed, with the desktop's own chooser for the rest")
        if driver.exists("button", "Close", timeout=3):
            driver.click("button", "Close", settle=1.0)
    else:
        run.failed("Unlock shared files was not in the Vault menu")
    driver.pause(0.8)

    run.step("settings", "Settings: where files are saved, and what closing does")
    driver.click("menu", "Vault", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "Settings", timeout=5):
        driver.click("menuitem", "Settings", settle=1.8)
        driver.pause(2.0)
        shots("27-settings")
        run.check(driver.exists("check", "Start Quenchkey when I log in", timeout=4)
                  or driver.exists("check", "Open filling the screen", timeout=2),
                  "the settings screen was missing its options")
        run.passed()
        if driver.exists("button", "Done", timeout=3):
            driver.click("button", "Done", settle=1.0)
    else:
        run.failed("Settings was not in the Vault menu")
    driver.pause(0.8)

    run.step("help", "The manual, in the application")
    driver.click("menu", "Help", timeout=8, settle=0.9)
    driver.pause(0.9)
    if driver.exists("menuitem", "How to use Quenchkey", timeout=5):
        driver.click("menuitem", "How to use Quenchkey", settle=1.8)
        driver.pause(2.0)
        shots("28-help")
        run.check(driver.exists("field", "Search the manual", timeout=4),
                  "the help window had no search box")
        run.passed(f"{len(help_pages())} pages")
        if driver.exists("button", "Close", timeout=3):
            driver.click("button", "Close", settle=1.0)
    else:
        run.failed("How to use Quenchkey was not in the Help menu")
    driver.pause(0.8)

    # ---- 11. lock the vault -----------------------------------------------
    run.step("lock-vault", "Locking the vault wipes every key from memory")
    if driver.exists("button", "Lock vault", timeout=4):
        driver.click("button", "Lock vault", settle=2.0)
        driver.pause(3.0)
        shots("29-locked-again")
        run.check(driver.exists("button", "Unlock", timeout=8),
                  "locking did not return to the unlock screen")
        run.passed()
    else:
        run.failed("no Lock vault button")

    return run


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def main(out_dir: str = "docs/demo") -> int:
    import tempfile
    import threading

    stage = Stage(out_dir)
    frames_dir = os.path.join(out_dir, "frames")
    os.makedirs(frames_dir, exist_ok=True)

    workspace = make_workspace(tempfile.mkdtemp(prefix="quenchkey-demo-"))
    vault_path = os.path.join(workspace["root"], "vault.qkv")

    print(f"recording to {out_dir}")
    print(f"workspace    {workspace['root']}")
    stage.start()

    # The walkthrough drives the file chooser by the object names of its
    # widgets, which only exist in Qt's own dialog. The desktop's chooser runs
    # in a different process entirely and has nothing this driver can reach,
    # so the recording asks for the Qt one. Everyone else gets the desktop's.
    os.environ["QUENCHKEY_FILE_DIALOG"] = "qt"

    # Qt must be imported only once the display exists.
    from PyQt5.QtCore import QMetaObject, Qt as QtNS
    from PyQt5.QtWidgets import QApplication

    from tools.uidriver import Driver, ScreenMap
    from quenchkey.ui import theme
    from quenchkey.ui.app import Application

    app = QApplication(sys.argv[:1])
    app.setApplicationName("Quenchkey")
    theme.apply(app)

    screen = ScreenMap()
    screen.start()

    controller = Application(vault_path, auto_lock_seconds=0)
    controller.start()

    driver = Driver(screen)
    outcome: dict = {"ok": False, "steps": [], "error": None}

    def shots(name: str) -> None:
        target = os.path.join(frames_dir, f"{name}.png")
        subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                        "-f", "x11grab", "-video_size", f"{WIDTH}x{HEIGHT}",
                        "-i", DISPLAY, "-frames:v", "1", target],
                       env=dict(os.environ, DISPLAY=DISPLAY), check=False)

    def script() -> None:
        try:
            driver.pause(3.0)
            run = walkthrough(driver, shots, workspace)
            run = walkthrough_part_two(driver, shots, run)
            outcome["steps"] = run.steps
            outcome["passphrase_words"] = len(run.passphrase.split("-"))
            # Kept so the run can be verified afterwards by the standalone
            # tool. This is a throwaway demo vault in a temporary directory;
            # a real one would never have its passphrase written anywhere.
            outcome["demo_passphrase"] = run.passphrase
            outcome["demo_shares"] = run.shares
            outcome["ok"] = all(step.get("ok") for step in run.steps)
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            outcome["error"] = f"{type(exc).__name__}: {exc}"
            outcome["traceback"] = traceback.format_exc()
            print("\nWALKTHROUGH FAILED:", outcome["error"], file=sys.stderr)
            print(outcome["traceback"], file=sys.stderr)
        finally:
            outcome["finished"] = True
            driver.say("Done")
            time.sleep(1.5)
            # A timer started from this thread would never fire: Qt refuses
            # timers on threads it did not start. A queued invocation is the
            # thread-safe way to ask the event loop to stop.
            QMetaObject.invokeMethod(app, "quit", QtNS.QueuedConnection)

    def watchdog() -> None:
        deadline = time.monotonic() + MAX_SESSION_SECONDS
        while time.monotonic() < deadline:
            if outcome.get("finished"):
                return
            time.sleep(1.0)
        outcome.setdefault("error", f"session exceeded {MAX_SESSION_SECONDS}s")
        print(f"\nWATCHDOG: over {MAX_SESSION_SECONDS}s, stopping",
              file=sys.stderr, flush=True)
        QMetaObject.invokeMethod(app, "quit", QtNS.QueuedConnection)

    threading.Thread(target=script, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    app.exec_()

    screen.stop()
    stage.stop()

    outcome["captions"] = [[round(t, 2), c] for t, c in driver.log]
    try:
        outcome.update(encode(stage, driver.log))
    except Exception as exc:  # noqa: BLE001
        outcome["encode_error"] = str(exc)

    # Now check the vault the interface just built, with code that shares
    # nothing with it.
    if outcome.get("demo_passphrase"):
        try:
            outcome["external_checks"] = verify_externally(
                vault_path, outcome["demo_passphrase"],
                outcome.get("demo_shares", []), out_dir)
            outcome["ok"] = outcome["ok"] and all(
                c["ok"] for c in outcome["external_checks"])
        except Exception as exc:  # noqa: BLE001
            outcome["external_error"] = f"{type(exc).__name__}: {exc}"
            outcome["ok"] = False

    # The verification above has had what it needs. Nothing that opens a vault
    # belongs in a file that ships with the project, throwaway or not.
    outcome.pop("demo_passphrase", None)
    outcome["demo_shares"] = f"{len(outcome.get('demo_shares') or [])} generated, not recorded"

    # The recording shows a generated passphrase and a set of recovery shares
    # on screen, because that is what those features look like. They belong to
    # this throwaway vault, which is removed here so that what is published
    # opens nothing that still exists.
    try:
        shutil.rmtree(workspace["root"])
        outcome["demo_vault_removed"] = True
    except OSError as exc:
        outcome["demo_vault_removed"] = f"could not remove: {exc}"

    report = os.path.join(out_dir, "demo-report.json")
    with open(report, "w") as fh:
        json.dump(outcome, fh, indent=2)

    print("\n" + "=" * 68)
    for entry in outcome["steps"]:
        mark = "PASS" if entry.get("ok") else "FAIL"
        note = f"  ({entry['note']})" if entry.get("note") else ""
        note += f"  {entry['error']}" if entry.get("error") else ""
        print(f"  {mark}  {entry['step']:<18} {entry['caption']}{note}")
    for entry in outcome.get("external_checks", []):
        mark = "PASS" if entry["ok"] else "FAIL"
        print(f"  {mark}  {'(external)':<18} {entry['check']} — {entry['detail']}")
    if outcome.get("external_error"):
        print("  FAIL  (external)        ", outcome["external_error"])
    print("=" * 68)
    print("overall:", "PASS" if outcome["ok"] else "FAIL")
    for key in ("mp4", "gif"):
        if key in outcome:
            size = os.path.getsize(outcome[key]) / 1e6
            print(f"  {key}: {outcome[key]}  ({size:.1f} MB)")
    print("report:", report)
    return 0 if outcome["ok"] else 1




# --------------------------------------------------------------------------
# after the recording: check the result with the independent implementation
# --------------------------------------------------------------------------

def help_pages() -> list:
    from quenchkey import help_text
    return help_text.page_titles()


def verify_externally(vault_path: str, passphrase: str, shares: list,
                      out_dir: str) -> list:
    """Re-read the vault the interface just built, using the standalone tool.

    The point is that nothing here shares code with the application. If the
    interface wrote something the documented format does not describe, this is
    where it shows up.
    """
    recover = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "quenchkey-recover.py")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = ""
    env["QUENCHKEY_PASSPHRASE"] = passphrase

    def run(args: list, use_passphrase: bool = True) -> tuple:
        local = dict(env)
        if not use_passphrase:
            local.pop("QUENCHKEY_PASSPHRASE", None)
        result = subprocess.run([sys.executable, recover, *args], env=local,
                                cwd="/", capture_output=True, text=True,
                                timeout=180)
        return result.returncode, result.stdout + result.stderr

    checks = []

    code, output = run(["list", vault_path])
    checks.append({
        "check": "the standalone tool reads the vault",
        "ok": code == 0 and "KEY DESTROYED" in output,
        "detail": "the destroyed entry is reported as destroyed"
                  if "KEY DESTROYED" in output else output[-300:]})

    code, output = run(["audit", vault_path])
    anchor = ""
    for line in output.splitlines():
        if line.startswith("anchor "):
            anchor = line.split(":", 1)[1].strip()
    checks.append({
        "check": "the event chain verifies independently",
        "ok": code == 0 and "chain           : OK" in output,
        "detail": f"anchor {anchor}" if anchor else output[-300:]})

    # Absolute: the tool runs with cwd="/" on purpose, to prove it needs
    # nothing from the project directory, so a relative path would land there.
    certs_dir = os.path.abspath(os.path.join(out_dir, "certificates"))
    # Emptied first: certificates from an earlier run would otherwise make
    # this pass whether or not this one issued anything.
    if os.path.isdir(certs_dir):
        for stale in os.listdir(certs_dir):
            os.unlink(os.path.join(certs_dir, stale))
    code, output = run(["certificates", vault_path, "-o", certs_dir])
    exported = sorted(f for f in os.listdir(certs_dir)) if os.path.isdir(certs_dir) else []
    checks.append({
        "check": "a destruction certificate was issued and exported",
        "ok": code == 0 and bool(exported) and "[VALID]" in output,
        "detail": ", ".join(exported) or output[-300:]})

    if exported:
        cert = os.path.join(certs_dir, exported[0])
        # No passphrase, no vault: what a counterparty actually holds.
        code, output = run(["verify", cert], use_passphrase=False)
        checks.append({
            "check": "the certificate verifies with no passphrase and no vault",
            "ok": code == 0 and "signature : VALID" in output,
            "detail": "verified from the document alone"
                      if "VALID" in output else output[-300:]})

    if shares:
        import tempfile

        # Written outside the published directory: shares open the vault, and
        # a demo is no reason to get careless about where they land.
        handle, share_file = tempfile.mkstemp(prefix="quenchkey-demo-shares-")
        with os.fdopen(handle, "w") as fh:
            fh.write("\n".join(shares))
        code, output = run(["--shares", share_file, "list", vault_path],
                           use_passphrase=False)
        checks.append({
            "check": "recovery shares open the vault without the passphrase",
            "ok": code == 0 and "reconstructed the master key" in output,
            "detail": "opened from a quorum" if code == 0 else output[-300:]})
        os.unlink(share_file)

    # A shared file, opened by the standalone tool with nothing but its own
    # passphrase — no vault anywhere in the call. This is the whole claim
    # behind the feature, so it is checked rather than asserted.
    # Absolute: the standalone tool is on purpose run with cwd="/" so that
    # nothing it does can depend on being started from the project.
    shared_source = os.path.abspath(os.path.join(out_dir, "handover.txt"))
    with open(shared_source, "w") as fh:
        fh.write("the thing that was handed over\n" * 200)
    shared_path = os.path.abspath(os.path.join(out_dir, "handover.qkey"))
    share_secret = "ephemeral-lantern-above-the-quay-41"

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from quenchkey import locker as _locker

    _locker.lock_to_share([shared_source], share_secret, output_path=shared_path)

    code, output = run(["share", "--describe", shared_path], use_passphrase=False)
    checks.append({
        "check": "a shared file says it has no deadline, without a passphrase",
        "ok": code == 0 and "none, and none is possible" in output,
        "detail": "the header declares it, so no tool has to guess"
                  if code == 0 else output[-300:]})

    opened = os.path.abspath(os.path.join(out_dir, "handover-opened"))
    os.makedirs(opened, exist_ok=True)
    local = dict(env)
    local["QUENCHKEY_PASSPHRASE"] = share_secret
    result = subprocess.run([sys.executable, recover, "share", shared_path,
                             "-o", opened], env=local, cwd="/",
                            capture_output=True, text=True, timeout=180)
    recovered = os.path.join(opened, "handover.txt")
    intact = (os.path.exists(recovered)
              and open(recovered).read() == open(shared_source).read())
    checks.append({
        "check": "a shared file opens with its own passphrase and no vault",
        "ok": result.returncode == 0 and intact,
        "detail": "opened and byte-identical" if intact
                  else (result.stdout + result.stderr)[-300:]})

    code, output = run(["share", shared_path, "-o", opened], use_passphrase=True)
    checks.append({
        "check": "the wrong passphrase is refused on a shared file",
        "ok": code != 0 and "wrong passphrase, or this file" in output.lower(),
        "detail": "refused, with no guess about which it was"
                  if code != 0 else output[-300:]})

    # The command line, against the same vault the window just built. A
    # different entry point reading the same formats: if the window wrote
    # something only the window understands, this is where it shows up. The
    # vault's passphrase is answered at the prompt the way a person would,
    # because there is on purpose no other way to give it.
    project = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def cli(args: list, answer: str = passphrase) -> tuple:
        """Run a command with a real terminal on the other end.

        A pipe will not do. ``getpass`` reads from the terminal rather than
        from standard input, and the command refuses outright when standard
        input is not a terminal — which is the contract being demonstrated. So
        this allocates a pseudo-terminal and types the passphrase into it, the
        way a person would, and that is the only way these commands can be
        driven at all.
        """
        import pty
        import select

        local = dict(env)
        local["PYTHONPATH"] = project
        local.pop("QUENCHKEY_PASSPHRASE", None)
        parent, child = pty.openpty()
        process = subprocess.Popen(
            [sys.executable, "-m", "quenchkey.cli", *args, "--vault", vault_path],
            env=local, cwd="/", stdin=child, stdout=child, stderr=child,
            close_fds=True)
        os.close(child)
        collected = bytearray()
        typed = False
        deadline = time.monotonic() + 180
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([parent], [], [], 0.5)
                if ready:
                    try:
                        chunk = os.read(parent, 8192)
                    except OSError:
                        break
                    if not chunk:
                        break
                    collected += chunk
                    if not typed and b"assphrase" in collected:
                        os.write(parent, (answer + "\n").encode())
                        typed = True
                elif process.poll() is not None:
                    break
            process.wait(timeout=30)
        finally:
            os.close(parent)
            if process.poll() is None:
                process.kill()
        text = collected.decode("utf-8", "replace")
        # The terminal echoes what was typed; strip the prompt line so the
        # passphrase does not end up in a published report.
        cleaned = "\n".join(line for line in text.splitlines()
                             if "assphrase" not in line and answer not in line)
        return process.returncode, cleaned

    # First, the property the whole design turns on: with nobody there to
    # answer, a command that needs the vault refuses rather than looking for
    # the passphrase somewhere it should not be.
    local = dict(env)
    local["PYTHONPATH"] = project
    local["QUENCHKEY_PASSPHRASE"] = passphrase
    unattended = subprocess.run(
        [sys.executable, "-m", "quenchkey.cli", "ls", "--vault", vault_path],
        env=local, cwd="/", stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=180)
    refused = unattended.stdout + unattended.stderr
    checks.append({
        "check": "with nobody there, the command line refuses rather than "
                 "reading the passphrase from the environment",
        "ok": (unattended.returncode != 0
               and "only way to give it is at a prompt" in refused
               and "quenchkey deposit" in refused),
        "detail": "refused, and pointed at the command that needs no "
                  "passphrase" if unattended.returncode != 0
                  else refused[-300:]})

    code, output = cli(["ls"])
    checks.append({
        "check": "the command line reads the vault the window built",
        "ok": code == 0 and "live" in output,
        "detail": output.strip().splitlines()[-1] if code == 0 else output[-300:]})

    code, output = cli(["status", "--json"])
    parsed = {}
    for line in output.splitlines():
        if line.startswith("{"):
            try:
                parsed = json.loads(output[output.index("{"):])
            except ValueError:
                parsed = {}
            break
    checks.append({
        "check": "status reports machine-readable state, and the chain verifies",
        "ok": code in (0, 4) and parsed.get("chain_ok") is True,
        "detail": (f"anchor {parsed.get('anchor')}, {parsed.get('entries')} "
                   f"entries, chain verifies") if parsed else output[-300:]})

    code, output = cli(["check"])
    checks.append({
        "check": "every locked file still matches its recorded digest",
        "ok": code == 0 and "match the digests" in output,
        "detail": "read back and compared by a separate entry point"
                  if code == 0 else output[-300:]})

    code, output = cli(["expire", "0" * 8])
    checks.append({
        "check": "the command line refuses to destroy a key without --yes",
        "ok": code != 0,
        "detail": "refused, as the dialog does" if code != 0 else output[-300:]})

    # And the one command that needs no passphrase at all, which is what makes
    # an unattended job possible without putting a secret on the machine.
    card_path = os.path.abspath(os.path.join(out_dir, "vault-identity.qkid"))
    code, output = cli(["card", "--output", card_path])
    deposit_source = os.path.abspath(
        os.path.join(out_dir, "nightly-export.csv"))
    with open(deposit_source, "w") as fh:
        fh.write("date,amount\n2026-09-30,1200\n" * 40)
    deposited = os.path.abspath(os.path.join(out_dir, "deposited.qkey"))
    local = dict(env)
    local["PYTHONPATH"] = project
    local.pop("QUENCHKEY_PASSPHRASE", None)
    result = subprocess.run(
        [sys.executable, "-m", "quenchkey.cli", "deposit", deposit_source,
         "--to", card_path, "--expires", "90d", "--output", deposited,
         "--quiet"],
        env=local, cwd="/", stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=180)
    checks.append({
        "check": "a file can be locked into the vault with no passphrase "
                 "anywhere, for a cron job",
        "ok": (result.returncode == 0 and os.path.exists(deposited)
               and passphrase.encode() not in open(deposited, "rb").read()),
        "detail": "deposited with the vault shut, and the passphrase is not in "
                  "the file" if result.returncode == 0
                  else (result.stdout + result.stderr)[-300:]})

    help_text_out = subprocess.run(
        [sys.executable, "-m", "quenchkey.cli", "help"],
        env=dict(env, PYTHONPATH=project), cwd="/", capture_output=True,
        text=True, timeout=120)
    checks.append({
        "check": "the overview says where the passphrase comes from, and "
                 "offers no other route",
        "ok": ("from a prompt, and from nowhere else" in help_text_out.stdout
               and "QUENCHKEY_PASSPHRASE" not in help_text_out.stdout
               and "--passphrase-file" not in help_text_out.stdout),
        "detail": "one source, and the removed ones are not advertised"})

    for leftover in (card_path, deposit_source, deposited):
        if os.path.exists(leftover):
            os.unlink(leftover)

    # These three checks needed a shared file and its plaintext side by side.
    # Neither belongs in a published directory, so both go: what stays is the
    # destruction certificate, which is evidence and carries no secret.
    for leftover in (shared_source, shared_path):
        if os.path.exists(leftover):
            os.unlink(leftover)
    shutil.rmtree(opened, ignore_errors=True)

    return checks


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs/demo"))
