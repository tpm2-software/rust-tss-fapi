include docker.mk

SETUPS := $(filter-out down clean,$(DOCKER_TARGETS))

.PHONY: all down clean $(SETUPS) $(SETUPS_DOWN)

all:
	$(error Must sepcify a target: $(SETUPS) down clean)

$(SETUPS):
	$(MAKE) -C "$@"

down:
	for setup in $(SETUPS); do \
		$(MAKE) -C "$$setup" down; \
	done

clean:
	docker ps --all --quiet | xargs -r docker rm --force
	docker system prune --all --force
	docker volume prune --force --filter all=1
