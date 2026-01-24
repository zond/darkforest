# Agent Instructions

Always give the user your honest and carefully considered opinion. Never assume something is
correct or positive just because the user claims so or seems to want it. Trust the user, but
verify their statements when possible. Don't glaze or be a yes-man, be a trustworthy expert,
consultant, and analyst.

## Development Workflow

Run the `date` command to understand what date it is today, because it's not 2025 anymore.

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
6. If you used review agents, add a note to the commit explaining which agents.
7. Fix any high priority issues identified by code review before committing
8. Add low/medium priority improvements to docs/future-work.md or TODO comments

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

### Embedded-Friendly Code

This project targets embedded devices. Follow these rules:

- **No recursion** - use iterative algorithms instead
- **No large stack allocations** - use heap (`Vec`, `Box`) for buffers >64 bytes
- **Limit call depth** - avoid deeply nested function calls (>8 levels)
- **Prefer bounded collections** - validate sizes at decode time, use MAX_* constants
- **No floating point in hot paths** - integer arithmetic preferred (libm only for fraud detection)
