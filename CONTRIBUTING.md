# Contribution Guidelines

Please note that this project is released with a
[Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this
project you agree to abide by its terms.

---

Ensure your pull request adheres to the following guidelines:

- Keep the `powershell` and `python` runtimes in parity, and update [`README.md`](README.md) when an input or behavior changes.
- Add or update tests for the code you change, and run them: `Invoke-Pester -Path tests/Action_tests.ps1, tests/Sync-VendoredModules_tests.ps1 -ExcludeTagFilter SkipCI` and `pytest tests/test_action.py` (install the Python test dependencies with `pip install -r requirements-dev.txt`).

Thank you for your suggestions!

## Updating your PR

A lot of times, making a PR adhere to the standards above can be difficult.
If the maintainers notice anything that we'd like changed, we'll ask you to
edit your PR before we merge it. There's no need to open a new PR, just edit
the existing one. If you're not sure how to do that,
[here is a guide](https://github.com/RichardLitt/knowledge/blob/master/github/amending-a-commit-guide.md)
on the different ways you can update your PR so that we can merge it.

## Updating PowerShell module dependencies

The PowerShell runtime loads its modules only from the vendored [`modules/`](modules) folder. Three files work together:

- [`requirements.psd1`](requirements.psd1): the pinned versions (edit this one).
- [`requirements.lock.psd1`](requirements.lock.psd1): the SHA512 of each pinned package (`sha512`) and a digest of the files extracted into `modules/<name>/<version>` (`contentSha512`). Generated, do not edit by hand.
- [`scripts/Sync-VendoredModules.ps1`](scripts/Sync-VendoredModules.ps1): downloads each pinned package, verifies its SHA512, and extracts it into `modules/`.

To bump a module:

1. Change the version in `requirements.psd1` and merge it to `main`.
2. The [Vendor PowerShell Modules](.github/workflows/vendor-pwsh-modules.yml) workflow runs the sync script and opens a PR with the updated `modules/` and `requirements.lock.psd1`. A new version is only accepted if its hash matches the one the PowerShell Gallery publishes; a version already in the lock file must match the recorded hash.
3. Review the module diff, then close and reopen the PR so CI runs (PRs opened with `GITHUB_TOKEN` do not trigger workflows), and merge it.

You can also run `./scripts/Sync-VendoredModules.ps1` locally and commit the result in the same PR. Run `./scripts/Sync-VendoredModules.ps1 -Check` to verify (offline) that `modules/` and the lock file match `requirements.psd1` and that no vendored file was modified, added, or removed. The Release workflow runs the same check and refuses to publish on a mismatch. `.gitattributes` marks `modules/` as binary so git does not rewrite line endings in the vendored files.

## Releasing

Run the [Release](.github/workflows/release.yml) workflow with a `version` (for example `3.0.1`) or a `bump` (`patch`, `minor` or `major`). It verifies `modules/` (see above), tags the release (`vX.Y.Z`), moves the `vX` and `vX.Y` tags (except for pre-releases), creates the GitHub release, and opens a PR that updates the SHA-pinned `uses:` lines in the README.
