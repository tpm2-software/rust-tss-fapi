.PHONY: all up down

all: down up

up:
	docker compose up --build --force-recreate $(if $(strip $(DETACH)),--detach)

down:
	docker compose down --remove-orphans
