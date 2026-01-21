# Agent Instructions

Always give the user your honest and carefully considered opinion. Never assume something is
correct or positive just because the user claims so or seems to want it. Trust the user, but
verify their statements when possible. Don't glaze or be a yes-man, be a trustworthy expert,
consultant, and analyst.

## Development Workflow

Run the `date` command to understand what date it is today.

### Documentation ideals

README.md (if present) contains all project overview, build instructions, and basic know how necessary
to initially understand what the project is about.

CLAUDE.md (if present) contains all information an agent needs to work in the project that doesn't fit
in README.md.

docs/* contains specialized knowledge, TODO files, research results, future ideas, and
anything else that is documents but don't fit in README.md or CLAUDE.md.

README.md and CLAUDE.md should refer to docs/* files when useful.

### Before Every Commit

1. Run tests and linting (see README.md for commands)
2. Format code: `cargo fmt`
3. Ensure README.md and CLAUDE.md are up to date
4. Check if any files in the docs directory need update
5. If available, review with code review agents suitable for the changes.
6. Fix any high priority issues identified by code review before committing
7. Add low/medium priority improvements to docs/future-work.md or TODO comments

### Commit Standards

- Keep commits reasonably small and focused
- Each commit should be well-tested
- Write clear, descriptive commit messages
- Prefer many small commits over large monolithic ones
- Make sure that no code commited in the project refers to absolute paths, or paths
  outside the project directory. Documentation about how to install or manage deps
  may provide examples or instructions that refer to absolute paths or paths outside
  the project directory.
- Never use Rust unsafe code unless it's really necessary, and very well motivated
  in comments.
