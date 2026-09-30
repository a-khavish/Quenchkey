**What this changes, and why**

**How you checked it**
- [ ] `python -m pytest`
- [ ] `python -m ruff check --select F,E --line-length 100 .`
- [ ] `xvfb-run -a python tools/dialog_parade.py` — if any dialog changed
- [ ] A test that fails without this change

**If this adds or changes a feature**
- [ ] Anything it cannot do is stated in the dialog that offers it, not only
      in the documentation
- [ ] The README, `SECURITY.md` and the in-app manual agree with each other
- [ ] No claim here is stronger than what the code does
