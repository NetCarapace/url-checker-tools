set -a; source .envdev; set +a
uv run url-checker --robot --verbose --misp-report 'http://malware.wicar.org/data/eicar.com' --sid Test_sus
