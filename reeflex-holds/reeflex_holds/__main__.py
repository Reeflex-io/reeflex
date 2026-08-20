"""__main__.py -- enables `python -m reeflex_holds` (stdio MCP server with no
args; `list`/`approve`/`reject` CLI subcommands with any -- see server.main())."""

from .server import main

if __name__ == "__main__":
    main()
