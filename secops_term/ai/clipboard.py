"""Transport C — clipboard fallback.

Per brief v3 §7.3: when neither Claude Code headless nor MCP is
available, this transport copies the (sentinel-fenced) prompt to the
clipboard via ``pyperclip``, instructs the user to paste it into a
Claude.ai chat, and reads the response back via a caller-supplied
async callable.

The "callable for the response" indirection keeps this transport usable
from both the CLI (``input()``-based prompt) and the TUI (textarea
modal). Neither layer leaks into the bridge.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import ModuleType
from typing import cast

from secops_term.ai.bridge import AIBridgeError, wrap_untrusted

ResponseProvider = Callable[[str], Awaitable[str]]

# Sentinel for "auto-detect pyperclip"; distinct from explicit ``None``
# (which means "no clipboard module — fail fast"). Lets tests inject
# ``None`` to simulate a system without pyperclip.
_AUTO_DETECT = object()


class ClipboardUnavailable(AIBridgeError):
    """``pyperclip`` not importable or the clipboard backend not functional."""


class ClipboardBridge:
    """Transport C — clipboard fallback.

    Constructor accepts ``response_provider`` so the call site can
    decide how to gather the user's pasted response:

    - CLI: a wrapper around ``input("paste response, end with EOF: ")``.
    - TUI: a modal that shows a multi-line textarea and resolves on submit.
    - Tests: an async lambda that returns canned text.

    The bridge itself never reads from stdin and never blocks on UI
    state — keeps it transport-pure and trivially testable.
    """

    name = "clipboard"

    def __init__(
        self,
        *,
        response_provider: ResponseProvider,
        clipboard_module: ModuleType | None | object = _AUTO_DETECT,
        instruction_template: str | None = None,
    ) -> None:
        if clipboard_module is _AUTO_DETECT:
            clipboard_module = _try_import_pyperclip()
        # After resolution: either a ModuleType or None.
        self._clip: ModuleType | None = (
            clipboard_module if isinstance(clipboard_module, ModuleType) else None
        )
        self._provider = response_provider
        self._instruction = (
            instruction_template
            if instruction_template is not None
            else (
                "Prompt copied to clipboard. Paste into a Claude.ai chat, "
                "wait for the response, then paste the response back here."
            )
        )

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        untrusted_inputs: list[str] | None = None,
    ) -> str:
        if self._clip is None:
            raise ClipboardUnavailable("pyperclip not importable")
        wrapped = wrap_untrusted(prompt, system, untrusted_inputs)
        try:
            self._clip.copy(wrapped)
        except Exception as exc:
            # pyperclip raises a `PyperclipException` on most failures
            # (e.g. headless Linux without a clipboard provider). We
            # convert to our own error so callers don't have to care.
            raise ClipboardUnavailable(
                f"clipboard copy failed: {type(exc).__name__}: {exc}"
            ) from exc
        return await self._provider(self._instruction)

    async def health_check(self) -> bool:
        if self._clip is None:
            return False
        # Probe by reading the current clipboard contents; pyperclip's
        # `paste()` raises on broken backends without mutating state.
        try:
            self._clip.paste()
        except Exception:
            return False
        return True


def _try_import_pyperclip() -> ModuleType | None:
    """Optional dep — return None if not available so ``health_check`` flips False."""
    try:
        import pyperclip  # type: ignore[import-not-found,import-untyped,unused-ignore]
    except ImportError:
        return None
    return cast(ModuleType, pyperclip)


__all__ = ["ClipboardBridge", "ClipboardUnavailable", "ResponseProvider"]
