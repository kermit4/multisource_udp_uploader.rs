WORKING AND FULL FEATURED

(actually up to 19 hours now)

These repos are to show my Rust learning speed, the applicability of my non-Rust programming background to Rust, and my knowledge of Rust features:

https://github.com/kermit4/first_2_hours_of_rust     
https://github.com/kermit4/first_8_hours_of_rust     
https://github.com/kermit4/first_16_hours_of_rust      (this repo)

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
