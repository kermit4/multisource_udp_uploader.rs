default: src/main

%: %.rs
	cargo --color always build --release
