WORKING AND FULL FEATURED


This was made to show my Rust knowledge, the applicability of my non-Rust background to Rust programming, and knowledge of Rust features.  This is not a port so some time went into logic, too.  It could be useful, though, if you had multiple locations with a large file, with differing upload speeds, that you wanted to send to one place, or one source that may be changing IPs, rebooting, or otherwise be interrupted.

earlier versions 
https://github.com/kermit4/first_2_hours_of_rust     
https://github.com/kermit4/first_8_hours_of_rust     
https://github.com/kermit4/first_16_hours_of_rust      

If run with no args, it will listen for uploads.

Clients from different sources can participate in the upload.  Clients do not hold state about the transfer.

With args it will send a file.  

i.e.
```
cargo run &
./target/debug/udp_uploader /etc/passwd localhost:34254
```

should result in a file of the same content named by its sha256

