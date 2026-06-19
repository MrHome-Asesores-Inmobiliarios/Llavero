"""Master key in protected memory — Model A (Annex A 6, 7; Annex G 2).

The master key (MK) is derived once at unlock and held in memory for the
session, so each secret read/write is instant. This module keeps that
in-memory MK as safe as Python allows:

- **Out of swap:** the backing buffer's pages are locked with ``mlock``
  (POSIX) / ``VirtualLock`` (Windows) so the MK is not paged to disk. This
  pairs with swap-off / encrypted-swap on the server (Annex G 2).
- **Zeroized:** the buffer is overwritten with ``ctypes.memset`` on lock,
  logout, idle timeout, and shutdown — a real memory write, not a Python-level
  loop that an optimiser could elide.
- **Idle auto-lock:** the holder wipes the MK after a period of inactivity.
- **Never persisted:** both classes refuse pickling/copying, so the MK can
  never be written into a Django session, cache, or any serialised store. They
  also redact their ``repr`` so the key never reaches a log line.
- **No core dumps:** ``disable_core_dumps`` drops ``RLIMIT_CORE`` to 0,
  reinforcing the systemd ``LimitCORE=0`` from P1-T1.

PyNaCl 1.5 does not expose libsodium's ``sodium_malloc``/``sodium_mlock``/
``sodium_memzero``, so we call the OS primitives directly via ctypes. ``mlock``
is best-effort (it can fail without privilege or against RLIMIT_MEMLOCK); the
status is tracked but never fatal, since swap-off is the backstop.

Inherent limitation: to use the MK with PyNaCl's AEAD we must hand it a Python
``bytes`` (PyNaCl copies its inputs). That transient copy is short-lived and
cannot be wiped; ``mlock`` protects the long-lived copy, which is what matters
for swap. Annex A 6 already notes a live memory dump exposes a Model-A MK.
"""

import ctypes
import ctypes.util
import sys
import time

_SIZE = ctypes.c_size_t


def _load_page_locker():
    """Return (lock, unlock) callables over (addr, size) -> bool, or (None, None)."""
    try:
        if sys.platform == "win32":
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.VirtualLock.argtypes = [ctypes.c_void_p, _SIZE]
            k32.VirtualLock.restype = ctypes.c_int
            k32.VirtualUnlock.argtypes = [ctypes.c_void_p, _SIZE]
            k32.VirtualUnlock.restype = ctypes.c_int
            return (
                lambda addr, n: k32.VirtualLock(addr, n) != 0,
                lambda addr, n: k32.VirtualUnlock(addr, n) != 0,
            )
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        libc.mlock.argtypes = [ctypes.c_void_p, _SIZE]
        libc.mlock.restype = ctypes.c_int
        libc.munlock.argtypes = [ctypes.c_void_p, _SIZE]
        libc.munlock.restype = ctypes.c_int
        return (
            lambda addr, n: libc.mlock(addr, n) == 0,
            lambda addr, n: libc.munlock(addr, n) == 0,
        )
    except (OSError, AttributeError):
        return (None, None)


_LOCK, _UNLOCK = _load_page_locker()


class KeyBufferCleared(Exception):
    """Raised when a cleared SecureBuffer is read."""


class MasterKeyLocked(Exception):
    """Raised when the vault is locked (never unlocked, or auto-locked)."""


def disable_core_dumps() -> bool:
    """Drop RLIMIT_CORE to 0 for this process (POSIX). No-op off POSIX.

    Returns True if the limit was set. On Windows there is no RLIMIT_CORE; the
    systemd ``LimitCORE=0`` is the authoritative control in production (Linux).
    """
    try:
        import resource
    except ImportError:
        return False
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except (ValueError, OSError):
        return False


class SecureBuffer:
    """A page-locked, zeroizable buffer for sensitive bytes (the MK).

    Not serialisable and not copyable, so it can never be persisted into a
    session/cache or duplicated. ``raw_snapshot`` is a test-only hook used to
    prove zeroization.
    """

    __slots__ = ("_size", "_buf", "_addr", "_cleared", "locked_in_ram")

    def __init__(self, data):
        self._size = len(data)
        self._cleared = False
        self.locked_in_ram = False
        self._buf = ctypes.create_string_buffer(self._size)
        self._addr = ctypes.addressof(self._buf)
        ctypes.memmove(self._addr, bytes(data), self._size)
        if _LOCK is not None and self._size:
            self.locked_in_ram = bool(_LOCK(self._addr, self._size))

    def get(self) -> bytes:
        """A transient copy of the bytes for an immediate crypto operation."""
        if self._cleared:
            raise KeyBufferCleared("secure buffer has been cleared")
        return self._buf.raw[: self._size]

    def clear(self) -> None:
        """Zeroize the buffer and unlock its pages. Idempotent."""
        if self._cleared:
            return
        ctypes.memset(self._addr, 0, self._size)
        if self.locked_in_ram and _UNLOCK is not None:
            _UNLOCK(self._addr, self._size)
        self._cleared = True

    def raw_snapshot(self) -> bytes:
        """TEST-ONLY: read the raw backing bytes regardless of cleared state."""
        return self._buf.raw[: self._size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.clear()

    def __del__(self):
        try:
            self.clear()
        except Exception:  # noqa: S110 - __del__ must not raise; cannot log at shutdown
            pass

    def __repr__(self):
        return f"<SecureBuffer size={self._size} cleared={self._cleared}>"

    def __reduce__(self):
        raise TypeError("SecureBuffer cannot be serialised (it holds key material)")

    def __copy__(self):
        raise TypeError("SecureBuffer cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("SecureBuffer cannot be copied")


def get_system_mk() -> "SecureBuffer | None":
    """Return the in-process MasterKeyHolder's buffer for system (non-HTTP) callers.

    Used by management commands (e.g. run_integrations) that need the vault MK
    without an active HTTP session. Returns None if the vault is locked.

    This is intentionally separate from the HTTP-session holder to avoid coupling
    the vault memory module to the session module.
    """
    try:
        from apps.operators import sessions

        if sessions.is_vault_unlocked():
            # Borrow a transient bytes snapshot — never store it long-term
            return sessions._holder().get_master_key()
    except Exception:
        pass
    return None


class MasterKeyHolder:
    """Holds the session master key in a SecureBuffer with idle auto-lock.

    The MK is set by the unlock flow (P1-T7 -> here) and read for crypto
    operations. A Viewer session must never construct/unlock one (enforced at
    the session layer, P1-T16): a Viewer holds no MK.
    """

    __slots__ = ("_buf", "_idle_seconds", "_clock", "_last_activity")

    def __init__(self, idle_seconds=None, clock=time.monotonic):
        self._buf = None
        self._last_activity = None
        if idle_seconds is None:
            from django.conf import settings

            idle_seconds = settings.LLAVERO_IDLE_LOCK_SECONDS
        self._idle_seconds = float(idle_seconds)
        self._clock = clock

    def unlock(self, mk) -> None:
        """Take ownership of the MK. If ``mk`` is a bytearray it is wiped after
        being copied into protected memory (the secured copy is the only one)."""
        self.lock()
        self._buf = SecureBuffer(mk)
        self._last_activity = self._clock()
        if isinstance(mk, bytearray):
            from apps.vault.crypto import wipe_buffer

            wipe_buffer(mk)

    def _is_idle(self) -> bool:
        return (
            self._last_activity is not None
            and (self._clock() - self._last_activity) >= self._idle_seconds
        )

    def is_unlocked(self) -> bool:
        return self._buf is not None and not self._is_idle()

    def enforce_idle(self) -> bool:
        """Wipe the MK if the idle window has elapsed. Returns True if locked."""
        if self._buf is not None and self._is_idle():
            self.lock()
        return self._buf is None

    def get_master_key(self) -> bytes:
        if self._buf is None:
            raise MasterKeyLocked("vault is locked")
        if self._is_idle():
            self.lock()
            raise MasterKeyLocked("vault auto-locked after idle timeout")
        self._last_activity = self._clock()
        return self._buf.get()

    def touch(self) -> None:
        if self._buf is not None and not self._is_idle():
            self._last_activity = self._clock()

    def lock(self) -> None:
        if self._buf is not None:
            self._buf.clear()
            self._buf = None
        self._last_activity = None

    def __del__(self):
        try:
            self.lock()
        except Exception:  # noqa: S110 - __del__ must not raise; cannot log at shutdown
            pass

    def __repr__(self):
        return f"<MasterKeyHolder unlocked={self.is_unlocked()}>"

    def __reduce__(self):
        raise TypeError("MasterKeyHolder cannot be serialised (it holds the master key)")

    def __copy__(self):
        raise TypeError("MasterKeyHolder cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("MasterKeyHolder cannot be copied")
