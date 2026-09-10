# Contributing

Thanks for taking a look. AistyMCP is alpha, so the API is still open to change.

## Getting set up

```bash
git clone https://github.com/AistyAI/AistyMCP.git
cd AistyMCP
pip install -e ".[dev]"
pytest -v
```

Python 3.10 or newer. There are no runtime dependencies, and adding one needs a
good reason.

## Before opening a pull request

- `pytest` passes.
- Every module still imports. CI checks this, because two of the modules were
  once reachable only through imports the tests did not make.
- New behaviour has a test. Anything touching `permission_model.py` needs one
  covering the denial path, not only the grant path.

## Things worth knowing

**`PermissionModel.has_permission` is the only decision point.** Everything else
delegates to it. If you add a way to reach a tool, add it there, so that
`get_allowed_tools` and composite servers cannot drift away from what
enforcement actually does.

**Constraints fail closed.** A constraint that cannot be evaluated denies. Keep
it that way.

**Grants do not cascade.** Granting one tool must not make another callable
unless the operator opted in explicitly, as `grant_reverse` does. This is what
lets someone enable "create" while leaving "delete" off.

## Style

Match what is there: standard library only, type hints on public signatures,
Google-style docstrings with an Args and Returns section, and a Raises section
wherever a function raises.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
