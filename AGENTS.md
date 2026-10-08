# Concurrent development

Use a separate Git worktree and feature branch for each person or agent working
at the same time. Worktrees isolate working files; task boundaries keep changes
to the same functions from conflicting during a merge.

Before editing, check `git status --short` and `git branch --show-current` in
your own worktree. Preserve work you did not create. Do not switch, reset,
clean, or stash another contributor's checkout.

Keep each task focused. Share its scope and the files or functions you expect
to change. When tasks touch the same functions, agree on their boundaries or
complete and merge the prerequisite task first.

## Current task boundary

`feat/target-path-comparison` contains the target-selection and ranked-route
comparison milestone. Its implementation and tests touch:

- `src/hexpath/cli.py`
- `src/hexpath/graph.py`
- `tests/test_cli.py`
- `tests/test_graph.py`
- `README.md`

Avoid duplicating this milestone in a concurrent task. If changing its code,
describe the additional behavior and coordinate any edits to the same functions.

`feat/ipv4-support` adds IPv4 scope validation, scanning, normalized records,
graph selection, CLI coverage, and documentation. It builds on
`feat/target-path-comparison` and touches:

- `src/hexpath/scope.py`
- `src/hexpath/scanner.py`
- `src/hexpath/models.py`
- `src/hexpath/cli.py`
- `src/hexpath/graph.py`
- their corresponding tests, `README.md`, and the example scope

Avoid parallel IPv4 or address-family changes until this branch is merged.

`feat/vulnerable-path-ranking` adds network-wide Dijkstra ranking on top of the
IPv4 branch. It touches the path-analysis section of `src/hexpath/graph.py`, the
graph and assessment command handling in `src/hexpath/cli.py`, their tests, and
the README. Avoid parallel path-ranking or Dijkstra changes until it is merged.

## Review and verification

Commit only the files belonging to your task. Open a separate pull request for
each task and merge one at a time. Run the full suite after combining branches:

```sh
PYTHONPATH=src python3 -m unittest discover --start-directory tests --verbose
```

A branch created from another feature branch depends on that feature. Merge the
prerequisite first, then target the default branch once it includes that work.
