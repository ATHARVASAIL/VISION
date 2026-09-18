"""Bounded parallelism for per-host enumeration.

Every enumeration stage was iterating hosts serially, so a /24 with 40 live
hosts cost `hosts × timeout` per stage — nearly four hours across the full
pipeline in the worst case, almost all of it spent blocked on network I/O.

These are subprocess calls waiting on sockets, so threads are the right tool:
no GIL contention, and the child processes run genuinely concurrently.

Concurrency is *bounded* rather than unlimited on purpose. An unbounded pool
against a /16 would fork thousands of processes, exhaust the local file-
descriptor limit, and look indistinguishable from a denial-of-service attempt
to the target's monitoring. Both outcomes end engagements badly.
"""

from __future__ import annotations


import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, Sequence, TypeVar

T = TypeVar("T")
R = TypeVar("R")

# Ceiling regardless of what the caller asks for. Above roughly this, the
# bottleneck stops being our concurrency and starts being the target's ability
# to answer — at which point we're just generating noise and false timeouts.
MAX_WORKERS = 24
DEFAULT_WORKERS = 12


def worker_count(requested: int | None = None, items: int | None = None) -> int:
    """Pick a sane worker count: never more workers than items of work, never
    more than the ceiling, never fewer than one.

    Deliberately *not* scaled by CPU count. Every task here blocks on a socket
    inside a child process and consumes essentially no local CPU, so tying the
    pool to core count throttles a 1-vCPU scanning VM to a quarter of its
    useful throughput for no benefit.
    """
    n = requested or DEFAULT_WORKERS
    if items is not None:
        n = min(n, max(1, items))
    return max(1, min(n, MAX_WORKERS))


def parallel_map(
    fn: Callable[[T], R],
    items: Sequence[T],
    workers: int | None = None,
    on_result: Callable[[R], None] | None = None,
) -> list[R]:
    """Run `fn` over `items` concurrently, returning successful results.

    A single host that hangs, refuses, or returns garbage must not take the
    stage down, so exceptions from `fn` are swallowed per item — the whole
    point of enumeration is that most probes fail.
    """
    items = list(items)
    if not items:
        return []
    if len(items) == 1:
        try:
            result = fn(items[0])
        except Exception:
            return []
        if result is None:
            return []
        if on_result:
            on_result(result)
        return [result]

    results: list[R] = []
    lock = threading.Lock()
    n = worker_count(workers, len(items))

    # The stage name lives in a thread-local, so a worker thread starts with an
    # empty one and every command it logs is attributed to "unknown". A real
    # run showed 10 searchsploit commands filed that way; on a network large
    # enough for any stage to fan out, that is every parallel stage's logging.
    # Capture it here and restore it inside each worker.
    from .pipeline import current_stage
    stage_name = current_stage()

    with ThreadPoolExecutor(max_workers=n, thread_name_prefix="vision") as pool:
        futures = {pool.submit(_guard, fn, item, stage_name): item
                   for item in items}
        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            with lock:
                results.append(result)
                if on_result:
                    on_result(result)
    return results


def _guard(fn: Callable[[T], R], item: T, stage_name: str = ""):
    """Run one item, swallowing its failure and restoring the stage name.

    The stage name lives in a thread-local, so a pool worker starts with an
    empty one and every command it runs is logged as "unknown". A real
    Metasploitable run filed 10 searchsploit commands that way; on a network
    large enough for any stage to fan out, it would be every parallel stage.
    """
    if stage_name:
        from .pipeline import current_stage
        current_stage(stage_name)
    try:
        return fn(item)
    except Exception:
        return None


def parallel_collect(
    fn: Callable[[T], Iterable[dict]],
    items: Sequence[T],
    workers: int | None = None,
) -> list[dict]:
    """Same as parallel_map, but `fn` returns zero-or-more findings per item
    and the results are flattened. This is the shape every enumeration stage
    wants."""
    batches = parallel_map(lambda i: list(fn(i) or []), items, workers=workers)
    return [finding for batch in batches for finding in batch]
