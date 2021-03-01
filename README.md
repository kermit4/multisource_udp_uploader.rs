WORKING AND FULL FEATURED

(actually up to 19 hours now)

This repo is only a snapshot to show my Rust learning speed, the applicability of my non-Rust background to Rust programming, and knowledge of Rust features.  This is not a port so some time went into logic, too.

https://github.com/kermit4/first_2_hours_of_rust     
https://github.com/kermit4/first_8_hours_of_rust     
https://github.com/kermit4/first_16_hours_of_rust      (this repo)

I'm now attempting to use more Rust features and development tools than necessary, as it was working after 8 hours and full featured after 14.

If run with no args, it will listen for uploads.

Clients from different sources can participate in the upload.  Clients do not hold state about the transfer.

With args it will send a file.  

i.e.
```
cargo run &
./target/debug/udp_uploader /etc/passwd localhost:34254
```

should result in a file of the same content named by its sha256
