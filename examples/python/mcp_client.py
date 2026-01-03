#!/usr/bin/env python3
"""
Example Python client for MCP System Info

This example demonstrates how to interact with mcp-sysinfo via HTTP.

Usage:
    python mcp_client.py                           # Uses default http://localhost:8080
    python mcp_client.py --url http://host:8080 --token mytoken
    python mcp_client.py --query get_cpu_info
    python mcp_client.py --list
"""

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any

try:
    import requests
except ImportError:
    print("Please install requests: pip install requests")
    sys.exit(1)


@dataclass
class Tool:
    """Represents an MCP tool."""
    name: str
    description: str


@dataclass
class Content:
    """Content item from a tool result."""
    type: str
    text: str = ""


@dataclass
class CallToolResult:
    """Result from calling a tool."""
    content: list[Content]
    is_error: bool = False


class MCPClient:
    """Client for MCP System Info server."""

    def __init__(self, base_url: str, token: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._id = 0

    def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Send a JSON-RPC request."""
        self._id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
        }
        if params:
            request["params"] = params

        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        response = requests.post(
            self.base_url,
            json=request,
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()
        if "error" in data and data["error"]:
            error = data["error"]
            raise RuntimeError(f"RPC error {error['code']}: {error['message']}")

        return data.get("result")

    def list_tools(self) -> list[Tool]:
        """List all available tools."""
        result = self._call("tools/list")
        tools = []
        for t in result.get("tools", []):
            tools.append(Tool(
                name=t["name"],
                description=t.get("description", ""),
            ))
        return tools

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> CallToolResult:
        """Call a tool and return the result."""
        params = {"name": name}
        if arguments:
            params["arguments"] = arguments

        result = self._call("tools/call", params)

        content = []
        for c in result.get("content", []):
            content.append(Content(
                type=c["type"],
                text=c.get("text", ""),
            ))

        return CallToolResult(
            content=content,
            is_error=result.get("isError", False),
        )


def pretty_print_json(text: str) -> None:
    """Pretty print JSON text."""
    try:
        parsed = json.loads(text)
        print(json.dumps(parsed, indent=2))
    except json.JSONDecodeError:
        print(text)


def main():
    parser = argparse.ArgumentParser(
        description="MCP System Info client example"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8080",
        help="MCP server URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Bearer token for authentication",
    )
    parser.add_argument(
        "--query",
        default=None,
        help="Query to run (e.g., get_cpu_info)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available tools",
    )
    args = parser.parse_args()

    client = MCPClient(args.url, args.token)

    if args.list:
        tools = client.list_tools()
        print(f"Available tools ({len(tools)}):")
        for tool in tools:
            print(f"  - {tool.name}: {tool.description}")
        return

    if args.query:
        # Run specified query
        result = client.call_tool(args.query)
        if result.is_error:
            print("Tool returned error", file=sys.stderr)
        for content in result.content:
            if content.type == "text":
                pretty_print_json(content.text)
        return

    # Run a few example queries
    queries = ["get_uptime", "get_cpu_info", "get_memory_info"]
    for query in queries:
        print(f"\n=== {query} ===")
        try:
            result = client.call_tool(query)
            if result.is_error:
                print("Tool returned error", file=sys.stderr)
                continue
            for content in result.content:
                if content.type == "text":
                    pretty_print_json(content.text)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
