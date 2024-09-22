SERVICE_NAME := $(firstword $(basename $(wildcard *.Dockerfile)))

.PHONY: all run down

all: down run

run:
	docker compose run --build --rm $(SERVICE_NAME)

down:
	docker compose down --remove-orphans
