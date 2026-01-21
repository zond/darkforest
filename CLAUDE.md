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