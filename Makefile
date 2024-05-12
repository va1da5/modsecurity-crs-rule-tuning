.PHONY: start
start:
	docker compose up -d

.PHONY: logs
logs:
	docker compose exec -it modsecurity tail -f /var/log/nginx/modsecurity.log || podman-compose exec modsecurity tail -f /var/log/nginx/modsecurity.log

.PHONY: restart
restart:
	docker compose restart modsecurity

.PHONY: test
test:
	pytest