#!/usr/bin/env bash
set -euo pipefail

forbidden_paths="$({
  git ls-files | awk '
    /(^|\/)\.env($|\.)/ && $0 !~ /\.env\.example$/ { print }
    /(^|\/)(\.my\.cnf|\.mylogin\.cnf|my\.cnf|my\.ini)$/ { print }
    /\.sql\.gz$/ { print }
    /\.(pem|key|p12|pfx|jks|keystore|crt|cer|der|kdb|bak|backup|dump|dmp|sql|mdf|ndf|ldf|ibd|frm|myd|myi|sqlite|sqlite3|db)$/ { print }
    /^docs\/evidence\/local\// { print }
    /^docs\/evidence\/.*\.local\.json$/ { print }
  '
} | sort -u)"

if [[ -n "$forbidden_paths" ]]; then
  echo "Sensitive or local-only files are tracked:" >&2
  echo "$forbidden_paths" >&2
  exit 1
fi

if git grep -nIE \
  'BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK|AKIA[0-9A-Z]{16}|(mysql2?|postgres(ql)?|mssql|sqlserver(\.database\.windows\.net)?):\/\/[^[:space:]]+:[^[:space:]@]+@' \
  -- ':!**/.env.example' ':!scripts/check-sensitive-files.sh'; then
  echo "Potential embedded credential material found in tracked content." >&2
  exit 1
fi

echo "No tracked sensitive-file patterns found."
