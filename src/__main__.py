"""
CloudKnife __main__ entry point.

Allows the package to be executed as: python -m cloudknife
This provides a more standard Python invocation method.
"""

from .cli import main

if __name__ == "__main__":
    main()
