include ../build/rstss.mk
include ../swtpm/swtpm.mk

.PHONY: all run down

all: down run

run:
	docker compose run --build --rm tests

down:
	docker compose down --remove-orphans
