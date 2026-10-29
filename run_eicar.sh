set -a; source .envdev; set +a
uv run src/url_checker_tools.py --robot --verbose --misp-report 'http://malware.wicar.org/data/eicar.com' --sid Test_sus
