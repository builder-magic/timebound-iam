# timebound-iam

A temporary AWS credential broker that runs as an [MCP](https://modelcontextprotocol.io/) server. It issues short-lived, service-scoped AWS credentials via STS AssumeRole so that AI coding agents (like Claude Code) can access AWS resources without long-lived keys. Credentials are time-bounded (15 minutes to 12 hours), scoped to specific services and access levels (read-only or full), and automatically cleaned up on expiry.

## Install

### Homebrew (macOS/Linux)

```bash
brew install builder-magic/tap/timebound-iam
```

### Go install

```bash
go install github.com/builder-magic/timebound-iam@latest
```

### Binary download

Download pre-built binaries from [GitHub Releases](https://github.com/builder-magic/timebound-iam/releases).

## Setup

### Configure AWS

Run the setup wizard to generate the IAM trust policy and inline policy for the broker role:

```bash
bin/timebound-iam setup aws
# or specify a named profile
bin/timebound-iam setup aws --profile my-profile
```

Follow the printed instructions to create the `timebound-iam-broker` IAM role in your account with the generated policies.

### Add to Claude Code

Register the MCP server so Claude Code can request temporary credentials on demand:

```bash
claude mcp add timebound-iam -- /path/to/bin/timebound-iam serve
```

Restart Claude Code to pick up the new server.

### Verify

Test the credential flow end-to-end:

```bash
bin/timebound-iam test
```

This requests short-lived S3 read-only credentials and writes them to a temporary `.env` file you can use to verify access.
