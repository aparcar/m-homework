bin/spoofer: src/spoofer.c
	mkdir -p bin
	cc src/spoofer.c -o bin/spoofer

check: bin/spoofer
	@which bats > /dev/null || (echo "Please install 'bats' for testing" && exit 1)

	@echo "Running tests"
	@bats tests/basic.bats

all: bin/spoofer

clean:
	rm -f bin/spoofer
	rmdir bin
