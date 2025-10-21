.PHONY: all clean

all:
	docker build -t tss2_builder .
	docker run --rm tss2_builder

clean:
	docker system prune --all --force
