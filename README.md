# 📛 OWASP ModSecurity Core Rule Set Tuning Practice

**Disclaimer**: _Work in progress_

[This collection](./test_waf.py) of basic unit tests is designed for practicing how to adjust [ModSecurity WAF rules](https://owasp.org/www-project-modsecurity-core-rule-set/) to pass each test. It's important to note that these tests are not reflective of real-life situations and are solely intended for honing your skills in tuning WAF rules in different scenarios.

## Getting Started

```bash
# Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

```bash
# Start WAF and placeholder web application
docker compose up -d

# Monitor WAF logs
docker compose exec -it modsecurity tail -f /var/log/nginx/modsecurity.log
podman-compose exec modsecurity tail -f /var/log/nginx/modsecurity.log

# Use BurpSuite proxy for request inspection
export HTTP_PROXY=http://localhost:8080
```

## WAF Tuning

```bash
# Run all tests
pytest

# Run individual test
pytest -k test_cookie_1
```

## References

- [owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)
- [OWASP ModSecurity Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/)
- [coreruleset/coreruleset](https://github.com/coreruleset/coreruleset)
- [OWASP CRS Docker Image](https://github.com/coreruleset/modsecurity-crs-docker)
- [Handling False Positives with the OWASP ModSecurity Core Rule Set](https://www.netnea.com/cms/apache-tutorial-8_handling-false-positives-modsecurity-core-rule-set/)
