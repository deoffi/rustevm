build:
	cargo build

run: build
	RUST_BACKTRACE=full cargo run

test:
	RUST_BACKTRACE=full cargo test
