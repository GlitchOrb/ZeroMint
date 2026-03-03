"""Clean utility module — should score very low for hotspots."""


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


def greet(name: str) -> str:
    """Say hello."""
    return f"Hello, {name}!"


class Calculator:
    """Simple calculator."""

    def multiply(self, x: float, y: float) -> float:
        return x * y

    def divide(self, x: float, y: float) -> float:
        if y == 0:
            raise ValueError("Division by zero")
        return x / y
