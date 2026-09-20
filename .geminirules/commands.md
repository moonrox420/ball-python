### Terminal & Command Execution Rules:
1. NEVER modify, append flags to, or alter a command to bypass an error (e.g., do NOT use `|| true`, `--skip-checks`, `--force`, or suppress exit codes).
2. NEVER use fake, temporary, or inline environment variables (like `CI=true` or dummy keys) just to make a command pass unless explicitly asked.
3. If a command fails in the default project environment, the implementation code is broken—FIX THE CODE, do not alter the command.
4. All commands must be written for my exact host environment:  Windows PowerShell running from the repo root directory.
5. Only suggest/run the standard project scripts defined in [package.json / Makefile / pyproject.toml / etc.]. Do not invent custom ad-hoc CLI flags.