# pgseatbelt

## Git

- All commits go on `main`. There is no need to create a separate branch, or a pull request, for a change.
- A session that runs in a git worktree on a branch of its own brings its commits onto `main` with a
  fast-forward merge from the main checkout (`git merge --ff-only <branch>`), instead of leaving them on
  that branch.
