#!/usr/bin/env python3
"""Main entry point that delegates to the url_checker_tools CLI with full argument support."""

import sys
from pathlib import Path

# Add src directory to Python path so imports work correctly
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

if __name__ == "__main__":
    # Import and run the main CLI function directly
    from url_checker_tools.cli import main

    # Run the CLI with all command line arguments
    main()
