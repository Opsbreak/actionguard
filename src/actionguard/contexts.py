"""Curated catalogue of attacker-controllable GitHub Actions contexts.

Patterns are dotted paths where ``*`` matches exactly one segment (an array index or an
object key). A pattern covers the value it names *and everything beneath it*.

Each entry has:

* ``level`` -- how widely the value is controllable: ``high`` means any GitHub user who
  can open an issue/PR/comment controls it; ``medium`` means it depends on a caller
  (``workflow_call`` inputs, composite action inputs); ``low`` means a user with write
  access is required (``workflow_dispatch`` inputs, ``repository_dispatch`` payloads).
* ``injectable`` -- whether the value can contain shell/JS metacharacters. Commit SHAs and
  PR numbers cannot, but they still identify attacker-controlled *code* and matter for
  checkout analysis (AG002).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

__all__ = ["DEFAULT_UNTRUSTED", "ContextCatalog", "UntrustedContext"]


@dataclass(frozen=True)
class UntrustedContext:
    pattern: str
    level: str = "high"
    injectable: bool = True

    @property
    def segments(self) -> tuple[str, ...]:
        return tuple(self.pattern.lower().split("."))


_HIGH_INJECTABLE = [
    # Issues, PRs, comments, reviews, discussions
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    # Branch names / labels of the head (fork) repository
    "github.head_ref",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.pull_request.head.repo.description",
    "github.event.pull_request.head.repo.homepage",
    # Commit metadata (author-controlled, also for pushes of merged contributor commits)
    "github.event.commits.*.message",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.commits.*.committer.email",
    "github.event.commits.*.committer.name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.head_commit.committer.email",
    "github.event.head_commit.committer.name",
    # Wiki (gollum)
    "github.event.pages.*.page_name",
    "github.event.pages.*.title",
    # workflow_run: data describing the triggering (possibly fork) run
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
    "github.event.workflow_run.head_commit.committer.email",
    "github.event.workflow_run.head_commit.committer.name",
    "github.event.workflow_run.head_repository.description",
    "github.event.workflow_run.pull_requests.*.head.ref",
    # check_suite / check_run on fork branches
    "github.event.check_suite.head_branch",
    "github.event.check_run.check_suite.head_branch",
]

# Not injectable (hex / integers / constrained names) but they point at attacker code.
_HIGH_REF_ONLY = [
    "github.event.pull_request.head.sha",
    "github.event.pull_request.merge_commit_sha",
    "github.event.pull_request.number",
    "github.event.pull_request.head.repo.full_name",
    "github.event.pull_request.head.repo.clone_url",
    "github.event.number",
    "github.event.issue.number",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_commit.id",
    "github.event.workflow_run.head_repository.full_name",
    "github.event.workflow_run.pull_requests.*.number",
    "github.event.workflow_run.pull_requests.*.head.sha",
    "github.event.check_suite.head_sha",
]

_LOW_INJECTABLE = [
    "github.event.client_payload",
]

DEFAULT_UNTRUSTED: tuple[UntrustedContext, ...] = (
    *(UntrustedContext(p, "high", True) for p in _HIGH_INJECTABLE),
    *(UntrustedContext(p, "high", False) for p in _HIGH_REF_ONLY),
    *(UntrustedContext(p, "low", True) for p in _LOW_INJECTABLE),
)

# Contexts that, inside a checkout ``ref:``/``repository:``, select the PR head.
# (A subset of the catalogue: e.g. ``issue.number`` only matters inside refs/pull/N/...).
CHECKOUT_REF_SOURCES = (
    "github.head_ref",
    "github.event.pull_request.head",
    "github.event.pull_request.merge_commit_sha",
    "github.event.pull_request.number",
    "github.event.number",
    "github.event.issue.number",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit",
    "github.event.workflow_run.head_repository",
    "github.event.workflow_run.pull_requests",
    "github.event.check_suite.head_sha",
    "github.event.check_suite.head_branch",
    # outputs of actions that resolve the PR behind a comment
    "xt0rted/pull-request-comment-branch output",
    "eficode/resolve-pr-refs output",
    "tj-actions/branch-names output",
)


def _seg_match(pattern_seg: str, path_seg: str) -> bool:
    return pattern_seg == "*" or path_seg == "*" or pattern_seg == path_seg


class ContextCatalog:
    """Matches normalised context paths against the untrusted catalogue."""

    def __init__(self, extra: Iterable[str | UntrustedContext] = ()) -> None:
        entries = list(DEFAULT_UNTRUSTED)
        for item in extra:
            if isinstance(item, UntrustedContext):
                entries.append(item)
            else:
                entries.append(UntrustedContext(str(item).strip().removesuffix(".*")))
        self.entries = tuple(entries)

    def match(self, path: tuple[str, ...], serialized: bool = False) -> list[UntrustedContext]:
        """Untrusted entries reached by ``path``.

        ``path`` matches an entry when it equals the entry or descends from it. When the
        value is serialised (``toJSON(github.event.issue)``) an *ancestor* of an entry also
        matches, because the whole object -- untrusted fields included -- is rendered.
        """
        hits: list[UntrustedContext] = []
        for entry in self.entries:
            segs = entry.segments
            if len(path) >= len(segs):
                if all(_seg_match(s, p) for s, p in zip(segs, path, strict=False)):
                    hits.append(entry)
            elif serialized and all(_seg_match(s, p) for s, p in zip(segs, path, strict=False)):
                hits.append(entry)
        return hits


def is_checkout_ref_source(path: str) -> bool:
    path = path.lower()
    return any(path == p or path.startswith(p + ".") for p in CHECKOUT_REF_SOURCES)
