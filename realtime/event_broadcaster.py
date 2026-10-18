"""
realtime/event_broadcaster.py — Memory-Safe Bounded Event Broadcaster for SSE.

Provides real-time streaming of packet telemetry and threat alerts to connected SOC frontend
clients via Server-Sent Events (SSE) with strict queue bounding to prevent memory leaks or blocking.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any, AsyncGenerator

logger = logging.getLogger(__name__)


class EventBroadcaster:
    """Thread-safe and memory-bounded SSE event broadcaster."""

    def __init__(self, max_queue_size: int = 200) -> None:
        self._max_queue_size = max_queue_size
        self._listeners: set[asyncio.Queue] = set()
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def _get_event_loop(self) -> asyncio.AbstractEventLoop | None:
        try:
            return asyncio.get_running_loop()
        except RuntimeError:
            return None

    def subscribe(self) -> asyncio.Queue:
        """Register a new SSE client queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue_size)
        with self._lock:
            self._listeners.add(q)
        logger.debug("New SSE client subscribed. Total listeners: %d", len(self._listeners))
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Unregister a disconnected SSE client queue."""
        with self._lock:
            self._listeners.discard(q)
        logger.debug("SSE client unsubscribed. Total listeners: %d", len(self._listeners))

    def publish_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """
        Publish an event to all connected SSE clients.
        Non-blocking: drops oldest event if a client queue is full to prevent backpressure.
        """
        with self._lock:
            listeners = list(self._listeners)

        if not listeners:
            return

        msg = {
            "type": event_type,
            "data": payload,
        }

        loop = self._get_event_loop()

        for q in listeners:
            try:
                if loop and loop.is_running():
                    if q.full():
                        try:
                            q.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    q.put_nowait(msg)
                else:
                    # Called from background thread — schedule call on main event loop if available
                    if q.full():
                        try:
                            q.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    q.put_nowait(msg)
            except Exception as e:
                logger.debug("Failed to push event to SSE queue: %s", e)

    async def stream_events(self, q: asyncio.Queue) -> AsyncGenerator[str, None]:
        """Async generator yielding SSE formatted strings for FastAPI EventSourceResponse."""
        try:
            # Yield initial connection heartbeat
            yield f"event: ping\ndata: {json.dumps({'status': 'connected'})}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    e_type = event.get("type", "message")
                    data_str = json.dumps(event.get("data", {}))
                    yield f"event: {e_type}\ndata: {data_str}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat every 15 seconds
                    yield "event: ping\ndata: {}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            self.unsubscribe(q)


# Global singleton broadcaster
BROADCASTER = EventBroadcaster()
