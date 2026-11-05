# Docs instructions

## Scope

Put a doc in `docs/` when it describes built, current behavior, or how to build, run, and check this repository. A design draft or plan is the exception when it has `status: draft` and the type `Design Draft`. Work that doesn't exist yet and isn't a draft belongs in the issue tracker.

## Format

`docs/` is an OKF v0.2 bundle. Each Markdown file in it, except `index.md`, `AGENTS.md` and `CLAUDE.md`, starts with YAML frontmatter that validates against [frontmatter.schema.json](schemas/frontmatter.schema.json). The [frontmatter reference](reference/frontmatter.md) lists the fields. Markdown files elsewhere in the repository, outside hidden directories, use the same frontmatter. Root files such as `README.md`, and `AGENTS.md` or `CLAUDE.md` in any directory, have no frontmatter and no index entry, because GitHub and the harnesses read them verbatim.

`index.md` is a reserved name. Only `docs/index.md` has frontmatter, and it holds only `okf_version: "0.2"`. List each doc in an `index.md`, one entry per line, in the form `* [Title](link) - description`, with a relative link. Use star markers in an index and dash markers elsewhere.

Name files in lowercase kebab-case, apart from the conventional `AGENTS.md`, `CLAUDE.md`, and `README.md`. Link between docs with relative links, and make each one resolve.

## Writing

Describe what the system is and does. Leave history and decision rationale to decision records. State facts that constrain behavior as constraints. Don't coin terms: use ordinary words or terms from the code or a standard. Write each paragraph on one line without hard wrapping. Use Mermaid for diagrams.

## Authorship fields

Fill `generated` from your own identity, with one entry per contributor. Its fields match the attributes of the `Generated-by` and `Assisted-by` commit trailers. Leave out a field you can't determine reliably instead of guessing it. Set `at` to the time of your last change, in Coordinated Universal Time with a `Z` suffix. When you change a doc another contributor wrote, add your own entry and keep the existing ones.

Never write `verified`. Only a human adds it, after reading the doc.

## Checks

Run `bazelisk test //:okf_docs_test` after each change. It validates the frontmatter of the bundle and of the other Markdown files. It also checks the index entries and that an index lists each doc. Run `bazelisk test //:rumdl_test` for structure and relative links, `bazelisk test //:vale_test` for prose, and `bazelisk test //:cspell_test` for spelling.
