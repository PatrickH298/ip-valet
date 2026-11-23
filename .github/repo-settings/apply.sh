#!/usr/bin/env bash
#
# Applies this repository's GitHub settings: branch and tag rulesets, merge
# options, Actions permissions and security features. Safe to re-run; it
# makes GitHub match these files.
#
#   .github/repo-settings/apply.sh                  # PatrickH298/ip-valet
#   .github/repo-settings/apply.sh OWNER/REPO
#
# Needs the GitHub CLI logged in as a repository admin (`gh auth status`).
#
# What it enforces:
#   * main can only change through a pull request. No direct pushes, force
#     pushes or deletion, for anyone.
#   * A pull request needs an approving review from a code owner, and
#     .github/CODEOWNERS names only @PatrickH298. Nobody else's approval can
#     satisfy the rule.
#   * GitHub does not let you approve your own pull request, so the
#     repository admin role may bypass the review requirement *when merging a
#     pull request* only ("pull_request" bypass mode). That is the owner
#     merging his own work; it does not allow pushing to main directly.
#   * Released version tags (v*) cannot be moved or deleted, so a published
#     version always points at the code it was built from. Creating new tags
#     is allowed (the release workflow does that).

set -euo pipefail

repo="${1:-PatrickH298/ip-valet}"
here="$(cd "$(dirname "$0")" && pwd)"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

command -v gh >/dev/null || { echo "The GitHub CLI (gh) is required." >&2; exit 1; }

# Create the ruleset if no ruleset of that name exists, otherwise replace it.
upsert_ruleset() {  # upsert_ruleset <json file>
  local file="$1" name id
  name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$file")
  id=$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id")
  if [[ -n "$id" ]]; then
    gh api -X PUT "repos/$repo/rulesets/$id" --input "$file" --silent
    echo "   updated ruleset '$name' ($id)"
  else
    gh api -X POST "repos/$repo/rulesets" --input "$file" --silent
    echo "   created ruleset '$name'"
  fi
}

say "Rulesets ($repo)"
upsert_ruleset "$here/ruleset-main.json"
upsert_ruleset "$here/ruleset-release-tags.json"

say "Repository options"
# The wiki on a public repository is editable by any GitHub user unless
# restricted, and nothing here uses it or Projects.
gh api -X PATCH "repos/$repo" --silent \
  -F delete_branch_on_merge=true \
  -F allow_update_branch=true \
  -F allow_auto_merge=false \
  -F has_wiki=false \
  -F has_projects=false
echo "   merged branches auto-delete; wiki and projects off"

say "GitHub Actions"
# Workflows get a read-only GITHUB_TOKEN unless a job asks for more, and
# cannot approve pull requests (which would otherwise satisfy a review rule).
gh api -X PUT "repos/$repo/actions/permissions/workflow" --silent \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=false
echo "   default token read-only; Actions cannot approve PRs"

# Workflows from forks never run until approved, for every outside
# contributor -- not only first-time ones.
gh api -X PUT "repos/$repo/actions/permissions/fork-pr-contributor-approval" --silent \
  -f approval_policy=all_external_contributors
echo "   fork PR workflows need approval for all outside contributors"

say "Security"
gh api -X PUT "repos/$repo/vulnerability-alerts" --silent
gh api -X PUT "repos/$repo/automated-security-fixes" --silent
gh api -X PUT "repos/$repo/private-vulnerability-reporting" --silent
gh api -X PATCH "repos/$repo" --silent --input - <<'JSON'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
JSON
echo "   Dependabot alerts + security updates, private vulnerability reporting,"
echo "   secret scanning and push protection on"

say "Done. Current rulesets:"
gh api "repos/$repo/rulesets" --jq '.[] | "   \(.name)  [\(.target), \(.enforcement)]"'
