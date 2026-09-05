# CI and release boundaries

Pull requests run on GitHub-hosted ephemeral runners with read-only repository
permissions. Checkout credentials are not persisted. No `pull_request_target`,
privileged PR completion workflow, self-hosted runner, or PR-to-release artifact
bridge is used. Event text must never be interpolated directly into shell scripts.
Actions are pinned to full commit IDs; Dependabot proposes reviewed updates.

The repository requires maintainer approval for all external contributors' fork
workflows. Approve a run only after reviewing executable changes, including build
scripts and dependencies. Approval does not make untrusted code safe. CI is not a
sandbox against a trusted administrator intentionally granting more permissions.

`main` requires PR gate and Native Windows checks, resolved conversations and
owner review of security-sensitive files via CODEOWNERS. Administrators retain
their recovery bypass; force pushes and deletion are disabled. This allows the
sole owner to maintain the project while protecting ordinary contributor paths.

## Release

1. Review and merge source to `main`, including license/source notices.
2. Tag that reviewed commit `vMAJOR.MINOR.PATCH`, matching the app manifest, and
   push the tag. Manual dispatch works only on such a tag.
3. CI checks that the tagged commit belongs to `main`, tests it and builds the
   archive and checksum with read-only permissions.
4. Approve the `github-release` environment after reviewing the run. Only `v*`
   tags may deploy there. The repository owner is the required reviewer.
5. An isolated publisher downloads that run's fixed-name artifact and creates a
   draft release. It never checks out source or executes the downloaded package.
   Only this job has `contents: write`.

Review licensing and native dependency source coverage before publishing a draft.
Current proposed commercial restrictions are not operative; see LICENSING.md.
No release tag is created by a normal source push. README changes appear on GitHub
as soon as their commit is pushed; no binary release is needed to review them.

Settings are repository-specific and must be rechecked after an organization
transfer. Environment approval can be performed by the sole owner even if they
triggered the run; it remains a deliberate deployment approval.
