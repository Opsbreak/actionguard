"""Static knowledge about events and third-party actions used by the rules."""

from __future__ import annotations

# Events whose runs get a privileged GITHUB_TOKEN and repository secrets even when the
# triggering content comes from an outside contributor.
PRIVILEGED_UNTRUSTED_TRIGGERS = frozenset(
    {
        "pull_request_target",
        "workflow_run",
        "issue_comment",
        "issues",
        "discussion",
        "discussion_comment",
    }
)

# Triggers for which AG002 (pwn request) applies: privileged + able to reach PR code.
PWN_REQUEST_TRIGGERS = frozenset({"pull_request_target", "workflow_run", "issue_comment"})

# Triggers that let outsiders schedule jobs (AG005 self-hosted runners).
PUBLIC_PR_TRIGGERS = frozenset(
    {
        "pull_request",
        "pull_request_target",
        "issue_comment",
        "pull_request_review",
        "pull_request_review_comment",
    }
)

# Triggers where a comment body drives the workflow (AG010).
COMMENT_TRIGGERS = frozenset({"issue_comment", "pull_request_review_comment", "discussion_comment"})

# Actions that execute code from the checked-out workspace (build scripts, package
# manager lifecycle hooks, Makefiles, Dockerfiles, ...).
BUILD_ACTIONS: tuple[str, ...] = (
    "docker/build-push-action",
    "docker/bake-action",
    "gradle/gradle-build-action",
    "gradle/actions/setup-gradle",
    "goreleaser/goreleaser-action",
    "pre-commit/action",
    "github/codeql-action/autobuild",
    "bahmutov/npm-install",
    "borales/actions-yarn",
    "cypress-io/github-action",
    "andresz1/size-limit-action",
    "preactjs/compressed-size-action",
    "ruby/setup-ruby",  # bundler-cache: true runs `bundle install`
    "pnpm/action-setup",  # run_install
    "nick-fields/retry",
    "nick-invision/retry",
    "coactions/setup-xvfb",
    "GabrielBB/xvfb-action",
    "addnab/docker-run-action",
    "JamesIves/github-pages-deploy-action",
    "peaceiris/actions-gh-pages",
    "maxim-lobanov/setup-xcode",
    "mxschmitt/action-tmate",
    "golangci/golangci-lint-action",
    "SonarSource/sonarqube-scan-action",
    "SonarSource/sonarcloud-github-action",
)

# Actions that check the commenter's permission level / team membership.
PERMISSION_CHECK_ACTIONS: tuple[str, ...] = (
    "actions-cool/check-user-permission",
    "prince-chrismc/check-actor-permissions-action",
    "sushichop/action-repository-permission",
    "lannonbr/repo-permission-check-action",
    "tspascoal/get-user-teams-membership",
    "TheModdingInquisition/actions-team-membership",
    "peter-evans/slash-command-dispatch",  # enforces `permission:` (default write)
    "xt0rted/slash-command-action",  # enforces `permission-level:`
    "skjnldsv/check-actor-permission",
)

# Actions whose outputs are attacker-controlled (file names, branch names, comment text).
# Values are glob patterns over output names.
TAINTED_OUTPUT_ACTIONS: dict[str, tuple[str, ...]] = {
    "tj-actions/changed-files": ("*",),
    "tj-actions/branch-names": ("*",),
    "jitterbit/get-changed-files": ("*",),
    "ana06/get-changed-files": ("*",),
    "dorny/paths-filter": ("*_files", "changes"),
    "xt0rted/pull-request-comment-branch": ("head_ref",),
    "peter-evans/find-comment": ("comment-body",),
    "actions-ecosystem/action-get-merged-pull-request": ("title", "body"),
    "eficode/resolve-pr-refs": ("head_ref",),
}

# Actions that download artifacts from *another* run (AG007).
CROSS_RUN_ARTIFACT_ACTIONS: tuple[str, ...] = (
    "dawidd6/action-download-artifact",
    "aochmann/actions-download-artifact",
    "bettermarks/action-artifact-download",
)

# Actions whose outputs identify pull-request *code* (SHAs/refs). Not injectable on their
# own, but checking them out under a privileged trigger is a pwn request (AG002).
REF_OUTPUT_ACTIONS: dict[str, tuple[str, ...]] = {
    "xt0rted/pull-request-comment-branch": ("head_sha", "head_ref"),
    "eficode/resolve-pr-refs": ("head_sha", "head_ref"),
    "tj-actions/branch-names": ("*",),
}
