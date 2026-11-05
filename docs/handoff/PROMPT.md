# Prompt for the AI that continues tikray

Paste the block below as the first message to a new AI assistant opened on the tikray folder.

```
You are taking over tikray, an xray-core client for MikroTik RouterOS v7, written in Go. It is
mid-way through milestone M2c. The project lives at C:\Users\Arman\Desktop\hakir\Projects\tikray,
which is /mnt/c/Users/Arman/Desktop/hakir/Projects/tikray inside WSL2 Ubuntu. The branch is
claude/serene-goldberg-1as8mu, and draft PR #6 (https://github.com/Arman2122/tikray/pull/6) shows it.

Before doing anything, read these in full, in this order:
1. AGENTS.md: the owner's binding rules.
2. docs/handoff/README.md: status, where the work stopped, the next steps, how to test, the code map.
3. docs/superpowers/specs/2026-10-24-tikray-design.md: the spec, the binding authority.
4. docs/superpowers/plans/2026-10-26-m2c-auth-hot.md: the M2c plan.
5. docs/handoff/m2c/ledger.md: every decision so far. A "Ruling:" line binds you like the plan.

The code builds only on Linux. Run every build and test command inside WSL2, e.g.
  wsl -e bash -lc "cd /mnt/c/Users/Arman/Desktop/hakir/Projects/tikray && make test"
If Go or make are missing, run scripts/dev-setup.sh there first. It installs them and runs the
unit tests, which must pass before you change anything.

Then continue with the "Next steps" in docs/handoff/README.md, one at a time:
1. Review Task 7 (git diff 791ce92..79f8582) against docs/handoff/m2c/task-7-brief.md,
   task-7-carries.md and the ledger's Task 7 rulings. Fix anything wrong, test-first.
2. Build Task 8 from docs/handoff/m2c/task-8-brief.md.
3. Build Task 9 from task-9-brief.md plus task-9-carries.md. The carries amend the brief. Task 9
   needs the RouterOS lab: root, KVM, QEMU and Docker (scripts/dev-setup.sh --lab). If this
   machine can't run it, say so and stop at that task. Don't fake its results.
4. Do a final review of the whole branch (main..HEAD) and fix what it finds, then update PR #6.

How to work:
- Work test-first. Write the failing test, watch it fail, make it pass, and keep `make test` green.
- Follow the surrounding code's style: stdlib first, errors prefixed with their package
  ("auth: ..."), comments that say why, the same naming.
- Decide things yourself like a senior engineer. Write each decision that departs from the plan
  into docs/handoff/m2c/ledger.md as "Ruling: <what> — <why> — <cost if wrong>", and record each
  finished task there.
- Never let a secret reach logs, errors, events, test output or results files. Secrets are share
  links, server credentials, subscription URLs, tokens, passwords, the setup code, session ids and
  CSRF values.
- Commit as Arman2122 <arman.seyri@gmail.com>, with no Co-Authored-By or any other trailers, and
  no AI model names in commits, PRs or code. Push only to claude/serene-goldberg-1as8mu.
- Never force-push, rewrite pushed history, or merge a PR without asking me first.
- After each task, tell me in a few plain sentences what changed and what the tests showed.
```
