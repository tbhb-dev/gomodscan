<!--
Fill in each section in plain prose and delete the guidance comments. Leave out
any section marked optional when there is nothing to say; don't write "None"
or "Low risk". Write each paragraph and list item on one line: GitHub
renders a newline as a line break, so a hard-wrapped paragraph shows ragged
short lines. The squash merge wraps the commit message. Word limits count
prose only: code blocks and links are free.

Agents don't use this form. They draft .github/PULL_REQUEST_DRAFT.md, which is
gitignored. Its frontmatter carries the metadata and its H1 is the title, and
the PR script lints the draft and opens the PR from it. The script also
appends the Generated-by and Assisted-by trailers as the body's last paragraph,
from the branch's commits and the posting agent's identity. Never write them.
-->

## Why

<!-- Required, at most 60 words. The problem in terms of behavior a user or
the system can see, in one to three sentences. Link the issue. -->

## Behavior change

<!-- Required, at most 120 words. What the system does differently now. Name a
file only when the file is itself the interface. -->

## Decisions

<!-- Optional, at most 120 words. Only choices worth recording, each as "chose
X over Y because Z". Leave the section out when nothing was decided beyond the
obvious. -->

## Deviations from the task

<!-- Optional, at most 80 words. Where the scope or approach changed from what
was asked, and why. -->

## Needs human judgment

<!-- Optional, at most 100 words. Open questions, guesses, and anything you
weren't confident about. -->

## Risk

<!-- Optional, at most 80 words. Specific failure modes and who they affect,
flags, rollback, and anything irreversible. -->

## Verification

<!-- Required, at most 150 words of prose plus any commands. Literal commands
with their results, or output from the command log. Leave out what CI already
reports. -->

## Human steering

<!-- Optional, at most 40 words. Who steered the work and how, when a person
did. Leave the section out for an autonomous run. -->
