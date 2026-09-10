#!/usr/bin/env bash
#
# Runs every test project.
#
# Not 'dotnet test': on the .NET 10 SDK that path still goes through the VSTest bridge,
# which Microsoft.Testing.Platform refuses. xunit.v3 test projects are self-executing, so
# running them directly is both supported and faster.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

status=0
for project in tests/*/*.csproj; do
  echo "==> ${project}"
  dotnet run --project "${project}" -v q -- "$@" || status=$?
done

exit "${status}"
