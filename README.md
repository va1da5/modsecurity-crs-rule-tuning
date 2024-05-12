# 📛 OWASP ModSecurity Core Rule Set Tuning Practice

**⚠️ Warning**: The solutions for these exercises are intended only for educational purposes and might not be production-ready.

[This collection](./test_waf.py) of basic unit tests is designed for practicing on how to adjust the [OWASP ModSecurity WAF Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/) to pass each test. It's important to note that these tests are not reflective of real-life situations and are solely intended for honing your skills in tuning WAF rules in different scenarios.

## Requirements

- Docker/Podman
- Docker Compose
- Python

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

# Restart container to apply new rules
docker compose restart modsecurity
podman-compose restart modsecurity

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

### Recommended Process

1. Start WAF and webserver `docker compose up -d`
2. Start monitoring of WAF logs `docker compose exec -it modsecurity tail -f /var/log/nginx/modsecurity.log`
3. Review test definition in [`test_waf.py`](./test_waf.py)
4. Execute individual test `pytest -k test_generic_form_1`
5. Review WAF log entries
6. Update WAF [rules](./waf)
7. Restart WAF `docker compose restart modsecurity`
8. Repeat steps 4 to 7 until test reports success.
9. Move to the next unit test.

## References

- [owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)
- [OWASP ModSecurity Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/)
- [coreruleset/coreruleset](https://github.com/coreruleset/coreruleset)
- [OWASP CRS Docker Image](https://github.com/coreruleset/modsecurity-crs-docker)
- [Handling False Positives with the OWASP ModSecurity Core Rule Set](https://www.netnea.com/cms/apache-tutorial-8_handling-false-positives-modsecurity-core-rule-set/)
- [SANS ModSecurity Rules](https://wiki.sans.blue/Tools/pdfs/ModSecurity.pdf)
- [ModSecurity Reference Manual (v3.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual)
- [Full pytest documentation](https://docs.pytest.org/en/8.2.x/contents.html)
