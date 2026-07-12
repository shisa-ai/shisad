"""Type-only helpers for handler mixins."""

from __future__ import annotations

import asyncio
import inspect
from typing import TYPE_CHECKING, Any


async def call_control_plane(handler: Any, method_name: str, /, *args: Any, **kwargs: Any) -> Any:
    target = getattr(handler._control_plane, method_name)
    result = target(*args, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


if TYPE_CHECKING:

    class HandlerMixinBase:
        """Allow extracted mixins to access HandlerImplementation attributes."""

        async def _call_control_plane(
            self, method_name: str, /, *args: Any, **kwargs: Any
        ) -> Any: ...

        def _terminate_session(self, session_id: Any, *, reason: str = "") -> bool: ...

        def _task_lifecycle_lock(self, task_id: str) -> asyncio.Lock: ...

        def _discard_task_lifecycle_lock_if_idle(
            self,
            task_id: str,
            lock: asyncio.Lock,
        ) -> None: ...

        async def _record_task_run_outcome(
            self,
            task_id: str,
            *,
            success: bool,
        ) -> bool: ...

        def __getattr__(self, name: str) -> Any: ...

else:

    class HandlerMixinBase:
        """Runtime no-op base class for handler mixins."""

        async def _call_control_plane(self, method_name: str, /, *args: Any, **kwargs: Any) -> Any:
            return await call_control_plane(self, method_name, *args, **kwargs)

        def _terminate_session(self, session_id: Any, *, reason: str = "") -> bool:
            terminated = bool(self._session_manager.terminate(session_id, reason=reason))
            if terminated:
                plan_steps = getattr(self, "_plan_steps", None)
                if plan_steps is not None:
                    plan_steps.clear_session(session_id=session_id)
            return terminated

        def _task_lifecycle_lock(self, task_id: str) -> asyncio.Lock:
            locks = getattr(self, "_task_lifecycle_locks", None)
            if not isinstance(locks, dict):
                locks = {}
                self._task_lifecycle_locks = locks
            lock = locks.get(task_id)
            if lock is None:
                lock = asyncio.Lock()
                locks[task_id] = lock
            return lock

        def _discard_task_lifecycle_lock_if_idle(
            self,
            task_id: str,
            lock: asyncio.Lock,
        ) -> None:
            if lock.locked() or bool(getattr(lock, "_waiters", None)):
                return
            locks = getattr(self, "_task_lifecycle_locks", None)
            if isinstance(locks, dict) and locks.get(task_id) is lock:
                locks.pop(task_id, None)

        async def _record_task_run_outcome(
            self,
            task_id: str,
            *,
            success: bool,
        ) -> bool:
            normalized_task_id = task_id.strip()
            scheduler = getattr(self, "_scheduler", None)
            recorder = getattr(scheduler, "record_run_outcome", None)
            if not normalized_task_id or not callable(recorder):
                return False
            recorded = bool(recorder(normalized_task_id, success=success))
            if not recorded or not success:
                return recorded

            get_task = getattr(scheduler, "get_task", None)
            task = get_task(normalized_task_id) if callable(get_task) else None
            if (
                task is None
                or not bool(getattr(task, "enabled", False))
                or int(getattr(task, "max_runs", 0)) <= 0
                or int(getattr(task, "success_count", 0)) < int(getattr(task, "max_runs", 0))
            ):
                return recorded

            disable_task = getattr(scheduler, "disable_task", None)
            if not callable(disable_task) or not bool(disable_task(normalized_task_id)):
                return recorded
            cancel_pending = getattr(self, "_cancel_pending_actions_for_task", None)
            if callable(cancel_pending):
                cancellation = cancel_pending(
                    normalized_task_id,
                    reason="max_runs_reached",
                )
                if inspect.isawaitable(cancellation):
                    await cancellation
            return recorded
