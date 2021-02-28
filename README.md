THIS IS JUST A DEMO OF MY RUST SKILL LEVEL AND LEARNING SPEED, IT IS NOT ACTUALLY VERY USEFUL

I'm now attempting to use more Rust features and development tools than necessary, as it was working after 8 hours and full featured after 14.

If run with no args, it will listen for uploads.

With args it will send a file.  

i.e.
```
cargo build
./target/debug/udp_uploader &
sleep 1
./target/debug/udp_uploader /etc/passwd 127.0.0.1:34254
```

should result in a file of the same content named by its sha256
