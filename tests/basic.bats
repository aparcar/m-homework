setup_file() {
	./bin/spoofer 4000 &
	echo $! > spoofer.pid
}

teardown_file() {
	kill "$(cat spoofer.pid)"
	rm spoofer.pid
}

#@test "spoof a" {
#	dig @127.0.0.1 -p 4000 a | grep "6.6.6.6"
#}

@test "spoof aa" {
	dig @127.0.0.1 -p 4000 aa | grep "6.6.6.6"
}

@test "spoof google.com" {
	dig @127.0.0.1 -p 4000 aa | grep "6.6.6.6"
}

@test "spoof example.org" {
	dig @127.0.0.1 -p 4000 aa | grep "6.6.6.6"
}

@test "spoof really long domain" {
	# random long string of 63 chars (max DNS fragment length
	FRAGMENT_63="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 63 | head -n 1)"
	FRAGMENT_61="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 61 | head -n 1)"

	# max dns length is 255 with max fragments of 63, so use 3*63 + 61 + 3 * dot
	dig @127.0.0.1 -p 4000 "$FRAGMENT_63.$FRAGMENT_63.$FRAGMENT_63.$FRAGMENT_61" | grep "6.6.6.6"
}

@test "test bad port argument" {
	./bin/spoofer foobar 2>&1 | grep "choose a valid port"
}
