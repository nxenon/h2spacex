# Contributing to H2SpaceX

Thanks for your interest in improving H2SpaceX! This guide covers the local
development setup, running tests, and how a release is built and published to
PyPI.

## Project layout

```
src/h2spacex/      # library source (the importable package)
examples/          # runnable Single Packet Attack examples
tests/             # unit tests
pyproject.toml     # single source of build config, metadata, and version
```

The build is driven entirely by `pyproject.toml` (setuptools backend). There is
no `setup.py`.

## Development setup

Use a virtual environment (Python >= 3.8.8):

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -e ".[dev]"           # editable install + dev tools (twine)
```

This installs the runtime dependencies (`scapy`, `brotlipy`, `PySocks`) plus the
`dev` extra used for publishing.

## Running tests

```bash
pip install pytest
pytest
```

The `tests/` suite can also be run without the heavy runtime dependencies — the
test files fall back to importing modules directly from `src/` when the package
is not installed:

```bash
python3 tests/test_utils.py
```

When you add a feature or fix a bug, please add or update a test where it is
practical to do so.

## Coding notes

- Keep changes backward compatible. Public methods on `H2Connection` /
  `H2OnTlsConnection` and the helpers in `h2_frames` are part of the API used by
  downstream exploits.
- Match the surrounding style (docstrings on public methods, `logger.logger_print`
  for output instead of bare `print`).

## Releasing a new version

Releases are published to [PyPI](https://pypi.org/project/h2spacex/). Only
maintainers can upload, but the full process is documented here for transparency.

1. **Bump the version** in `pyproject.toml` (`[project] version = "X.Y.Z"`).
   Follow [semantic versioning](https://semver.org/): patch for bugfixes,
   minor for backward-compatible features, major for breaking changes.

2. **Update the README**: bump the `pypi` badge version near the top and add a
   `## Change Log & Beta Versions` entry describing the changes.

3. **Commit and tag**:

   ```bash
   git commit -am "set version X.Y.Z"
   git tag vX.Y.Z
   git push && git push --tags
   ```

4. **Build the distributions** (wheel + source archive) in a clean tree:

   ```bash
   rm -rf dist build src/*.egg-info
   pip install build
   python -m build
   ```

   This produces `dist/h2spacex-X.Y.Z-py3-none-any.whl` and
   `dist/h2spacex-X.Y.Z.tar.gz`.

5. **Validate the metadata** before uploading:

   ```bash
   twine check dist/*
   ```

6. **Upload to PyPI** with twine (configure a PyPI API token via `~/.pypirc` or
   the `TWINE_USERNAME=__token__` / `TWINE_PASSWORD=<token>` environment
   variables):

   ```bash
   # optional: publish to TestPyPI first to verify
   twine upload --repository testpypi dist/*

   # production release
   twine upload dist/*
   ```

   > A published version is permanent — PyPI does not allow re-uploading the same
   > version number. Double-check the version and `twine check` output first.

7. **Verify** the release installs cleanly from PyPI:

   ```bash
   pip install --upgrade h2spacex
   ```

## Reporting issues

Open an issue at <https://github.com/nxenon/h2spacex/issues> with a clear
description and, where possible, a minimal reproduction.
