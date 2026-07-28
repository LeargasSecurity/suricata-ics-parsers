# CI workflow (manual install step required)

`ci/ci.yml` is the GitHub Actions workflow for this project. It is staged here
instead of `.github/workflows/` because it was committed with a Personal Access
Token that lacks the `workflow` scope (GitHub rejects workflow changes from such
tokens).

**To activate CI**, move it into place with a `workflow`-scoped token or via the
GitHub web UI:

```bash
mkdir -p .github/workflows
git mv ci/ci.yml .github/workflows/ci.yml
git commit -m "ci: enable GitHub Actions workflow"
git push
```

(Adding the file through the GitHub web editor also works and does not require
the `workflow` scope.)

Once installed, the CI badge in the README will begin reporting build status.
