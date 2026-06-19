from __future__ import annotations

from collections import deque
from typing import Deque, Generic, Iterable, Optional, TypeVar


T = TypeVar("T")


class AlertQueue(Generic[T]):
    def __init__(self, items: Optional[Iterable[T]] = None) -> None:
        self._queue: Deque[T] = deque(items or [])

    def put(self, alert: T) -> None:
        self._queue.append(alert)

    def get(self) -> T:
        if not self._queue:
            raise IndexError("AlertQueue is empty")
        return self._queue.popleft()

    def empty(self) -> bool:
        return not self._queue

    def size(self) -> int:
        return len(self._queue)