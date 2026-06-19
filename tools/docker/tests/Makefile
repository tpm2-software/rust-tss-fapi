TSSFAPI_TEST_BRANCH ?= stable

.PHONY: all run down

all: down run

run:
	docker compose -f docker-compose.$(TSSFAPI_TEST_BRANCH).yml run --build --rm tests

down:
	docker compose -f docker-compose.$(TSSFAPI_TEST_BRANCH).yml down --remove-orphans
