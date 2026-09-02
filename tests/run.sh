#!/usr/bin/env bash
# Runs the full test suite (unit + WP shim suites).
# Installs test dependencies into tests/vendor/ on first run — dev deps
# never touch the shipped includes/vendor directory.

set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -f vendor/autoload.php ]]; then
    composer install --no-interaction --prefer-dist --no-progress
fi

exec vendor/bin/phpunit --testdox -c ../phpunit.xml.dist "$@"
