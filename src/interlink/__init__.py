"""Interlink: drive any agent harness from any MCP client, inside throwaway sandboxes.

Interlink began life as the test-driving bridge inside PEGASUS. This package is the
harness-agnostic extraction of that idea: an MCP stdio server that launches disposable
instances of an agent harness, prompts them, watches what they do, and keeps an
evidence trail you can verify afterwards.
"""

__version__ = "0.2.2"
SCHEMA = "interlink/1"

__all__ = ["SCHEMA", "__version__"]
