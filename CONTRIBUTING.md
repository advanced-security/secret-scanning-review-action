# Contribution Guidelines

Please note that this project is released with a
[Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this
project you agree to abide by its terms.

---

Ensure your pull request adheres to the following guidelines:

- Make sure you take care of this
- And this as well
- And don't forget to check this

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
- [`requirements.lock.psd1`](requirements.lock.psd1): the SHA512 of each pinned package. Generated, do not edit by hand.
- [`scripts/Sync-VendoredModules.ps1`](scripts/Sync-VendoredModules.ps1): downloads each pinned package, verifies its SHA512, and extracts it into `modules/`.

To bump a module:

1. Change the version in `requirements.psd1` and merge it to `main`.
2. The [Vendor PowerShell Modules](.github/workflows/vendor-pwsh-modules.yml) workflow runs the sync script and opens a PR with the updated `modules/` and `requirements.lock.psd1`. A new version is only accepted if its hash matches the one the PowerShell Gallery publishes; a version already in the lock file must match the recorded hash.
3. Review the module diff, then close and reopen the PR so CI runs (PRs opened with `GITHUB_TOKEN` do not trigger workflows), and merge it.

You can also run `./scripts/Sync-VendoredModules.ps1` locally and commit the result in the same PR. Run `./scripts/Sync-VendoredModules.ps1 -Check` to verify `modules/` and the lock file match `requirements.psd1` (offline). The Release workflow runs the same check and refuses to publish on a mismatch.

## Floating version tag

Once you have a tag and release using the semver version, the last remaining thing to do is to move the dynamic version
identifier to match the current SHA. This allows users to adopt a
major version number (e.g. `v2`) in their workflows while
automatically getting all the
minor/patch updates.

To do this just checkout `main`, force-create a new annotated tag, and push it:

```bash
git checkout main
git pull origin main
git tag -fa v2 -m "Updating v2 to 2.2.3"
git push origin v2 --force
```
