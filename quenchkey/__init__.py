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

"""Quenchkey — files that expire for real.

Most "self-destructing file" tools delete the file, which does nothing about a
copy someone made last week. Quenchkey keeps the locked file and its key in
different places: the encrypted ``.qkey`` file lives wherever you want, the
key to it lives only inside the vault, and when a file expires it is the *key*
that is destroyed.

The encrypted file can then still exist — on any number of copies, on any
number of machines — and be permanently unreadable, because the only key that
ever opened it no longer exists anywhere.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
