"""Bounded graph search: breadth-first for the shortest path, depth-first for alternatives.

Both searches are iterative (no recursion limit), never revisit a node on the
current path (cycle protection) and stop at explicit limits, reporting that
they did so instead of running on.
"""

from __future__ import annotations

from collections import deque
from typing import Callable, Hashable, Iterable, TypeVar

Node = TypeVar("Node", bound=Hashable)


def shortest_path(successors: Callable[[Node], Iterable[Node]], start: Node, is_goal: Callable[[Node], bool], *,
                  max_depth: int, max_visited: int = 1_000_000) -> list[Node] | None:
    """The shortest path from `start` to a goal node (both included), or None within the limits. Breadth-first.

    Successors are visited in the order given, so the result is deterministic
    when that order is.
    """
    if is_goal(start):
        return [start]
    previous: dict[Node, Node | None] = {start: None}
    queue: deque[tuple[Node, int]] = deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for following in successors(node):
            if following in previous:
                continue
            previous[following] = node
            if is_goal(following):
                path = [following]
                cursor = node
                while cursor is not None:
                    path.append(cursor)
                    cursor = previous[cursor]
                path.reverse()
                return path
            if len(previous) >= max_visited:
                return None
            queue.append((following, depth + 1))
    return None


def simple_paths(successors: Callable[[Node], Iterable[Node]], start: Node, is_goal: Callable[[Node], bool], *, max_depth: int,
                 max_paths: int, max_expansions: int) -> tuple[list[list[Node]], bool]:
    """Simple paths from `start` to goal nodes, found depth-first. Returns (paths, truncated).

    A path may pass through a goal node and continue to another. `truncated`
    is True when a limit stopped the search before it was exhausted.
    """
    found: list[list[Node]] = []
    if max_paths <= 0:
        return found, True
    expansions = 0
    path: list[Node] = [start]
    on_path: set[Node] = {start}
    stack: list[Iterable[Node]] = [iter(())] if max_depth <= 0 else [iter(successors(start))]
    if is_goal(start):
        found.append([start])
    truncated = False
    while stack:
        if len(found) >= max_paths or expansions >= max_expansions:
            truncated = True
            break
        following = next(stack[-1], None)   # type: ignore[call-overload]
        if following is None:
            stack.pop()
            on_path.discard(path.pop())
            continue
        if following in on_path:
            continue                         # cycle protection: a node appears once per path
        expansions += 1
        path.append(following)
        on_path.add(following)
        if is_goal(following):
            found.append(list(path))
        if len(path) - 1 >= max_depth:
            if any(True for _ in successors(following)):
                truncated = True             # there was more to explore beyond the depth limit
            on_path.discard(path.pop())
            continue
        stack.append(iter(successors(following)))
    return found, truncated
