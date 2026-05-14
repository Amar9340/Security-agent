"""
ToolRegistry — collects tool functions and builds the dict that BaseAgent consumes.

Each tool function declares its LLM-visible schema via a __schema__ attribute:

    def http_request(...):
        ...
    http_request.__schema__ = {
        "name": "http_request",
        "description": "...",
        "parameters": {"type": "object", "properties": {...}, "required": [...]},
    }

Usage:
    from agents.tool_registry import build_registry
    from agents.tools.http_tool import http_request
    from agents.tools.finding_tool import report_finding

    registry = build_registry(http_request, report_finding)
    agent = BaseAgent(llm=..., tool_registry=registry, system_prompt=...)
"""
import logging

logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    Collects tool functions by name.
    Name is taken from __schema__["name"] if present, otherwise __name__.
    """

    def __init__(self):
        self._tools: dict = {}

    def register(self, fn) -> "ToolRegistry":
        name = _tool_name(fn)
        if name in self._tools:
            logger.warning(f"[REGISTRY] Overwriting existing tool: {name}")
        self._tools[name] = fn
        logger.debug(f"[REGISTRY] Registered: {name}")
        return self

    def build(self) -> dict:
        """Return the registry dict {name: callable} for use by BaseAgent."""
        return dict(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def __repr__(self) -> str:
        return f"ToolRegistry({list(self._tools)})"


def build_registry(*tool_fns) -> dict:
    """
    Convenience: build a registry dict from a flat list of tool functions.

    Example:
        registry = build_registry(http_request, dns_lookup, report_finding)
    """
    reg = ToolRegistry()
    for fn in tool_fns:
        reg.register(fn)
    logger.info(f"[REGISTRY] Built with {len(reg)} tools: {list(reg._tools)}")
    return reg.build()


def _tool_name(fn) -> str:
    schema = getattr(fn, "__schema__", None)
    if schema and "name" in schema:
        return schema["name"]
    return fn.__name__
