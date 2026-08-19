# CLAUDE.md

netsim is a generic topology simulator: it boots libvirt/QEMU VMs on virtual
networks so software can be tested against a real multi-host network. It knows
nothing about any particular product, and that is a property to preserve.

## Two halves

`netsim/` is the simulator — topology parsing, VM and network lifecycle, image
management, and the `netsim` CLI.

`netsim/testkit/` is the pytest layer built on it: an SSH `Node`, traffic and
systemd helpers, `BaseTopologyTests`, and `plugin.py` holding the fixtures and
CLI options. A consuming project gets all of it with one line in its rootdir
`conftest.py`:

```python
pytest_plugins = ["netsim.testkit.plugin"]
```

`tests/` holds netsim's own suites, which use that same entry point. They are
deliberately small — `two_node_iperf` and `three_node_iperf` — and exist to
prove the simulator and the plugin, not to test anything built on top.

## Keeping it generic

Nothing under `netsim/` may name a specific product. Fixtures, options and
docstring examples belong to the simulator, so a feature that only one
consumer needs belongs in that consumer's own `conftest.py` instead.

For the same reason `testkit` is a published surface: its helpers mostly have
no caller in this repo, which is why vulture skips it. Removing something
there breaks projects you cannot see from here.

Real consumers today: policy-engine, whose suites live in that repo under
`python/tests/`.

## Conventions worth knowing

A suite is a directory; its topology is `<dir>/<dir>.yaml`. The `topology_path`
fixture finds it by that convention alone.

Topology `packages` takes two forms. A plain list installs regardless of
`--feature`. The nested form declares per-feature sets and `pytest --feature
<name>` (default `vanilla`) picks one — that is how a suite runs against
several builds of the same software. Globs resolve against `--package-dir` or
the topology's `package_dir`, and `pytest_configure` validates every one of
them before a single VM boots.
