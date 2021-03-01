use bit_vec::BitVec;
use std::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::env;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::copy;
use std::mem::transmute;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Duration;

struct InboundState {
    file: File,
    len: u64,
    hash: [u8; 256 / 8],
    blocks_remaining: u64,
    next_missing: u64,
    requested: u64,
    highest_seen: u64,
    bitmap: BitVec,
    lastreq: u64,
    hash_checked: bool,
    dups: u64,
}

impl InboundState {
    fn new(content_packet: &ContentPacket) -> Result<InboundState, std::io::Error>  {
        Ok(InboundState {
                lastreq: 0,
                file:  // File::create(
				OpenOptions::new().create(true).read(true).write(true)
                    .open(Path::new(&hex::encode(content_packet.hash)))?,
                len: content_packet.len,
                blocks_remaining: blocks(content_packet.len),
                next_missing: 0,
                highest_seen: 0,
				hash_checked: false,
                hash: content_packet.hash,
                requested: 0,
                bitmap: BitVec::from_elem(blocks(content_packet.len) as usize, false),
                dups:0,
            })
    }

    fn handle_content_packet  (
        &mut self,
        content_packet: &ContentPacket,
        socket: &UdpSocket,
        src: &SocketAddr,
    )-> Result<(),std::io::Error> {
        if self.bitmap.get(content_packet.offset as usize).unwrap() {
            println!("dup: {}", content_packet.offset);
            self.dups += 1;
        } else {
            self.file
                .write_at(
                    &content_packet.data,
                    content_packet.offset * ContentPacket::block_size(),
                )
                ?;
            self.blocks_remaining -= 1;
            self.bitmap.set(content_packet.offset as usize, true);
            if content_packet.offset > self.highest_seen {
                self.highest_seen = content_packet.offset
            }
        }

        if self.blocks_remaining == 0 {
            if !self.hash_checked {
                self.check_hash()?;
                self.hash_checked = true;
                drop(&self.file); // free up a file descriptor
            }
            let encoded: Vec<u8> = bincode::serialize(&RequestPacket {
                offset: !0,
                hash: self.hash,
            })
            .unwrap();
            socket.send_to(&encoded[..], &src).expect("cant send_to");
        } else {
            self.request_more(socket, src);
        }
        Ok(())
    }

    fn request_more(&mut self, socket: &UdpSocket, src: &SocketAddr) {
        let mut request_packet = RequestPacket {
            offset: 0,
            hash: self.hash,
        };
        self.lastreq += 1;
        if self.lastreq >= blocks(self.len) {
            // "done" but just filling in holes now
            self.request_missing_or_next(&socket, &src);
            return;
        }

        request_packet.offset = self.lastreq;
        println!("requesting block {:>6}", request_packet.offset);
        let encoded: Vec<u8> = bincode::serialize(&request_packet).unwrap();
        socket.send_to(&encoded[..], &src).expect("cant send_to");
        self.requested += 1;

        if (self.requested % 100) == 0 {
            // push it to 1% packet loss
            self.request_missing_or_next(&socket, &src);
        }
    }

    fn check_hash(&mut self)  -> Result<(), std::io::Error> {
        // upload done

        self.file.set_len(self.len)?;
        println!(
            "received {} dups {}",
            &hex::encode(&self.hash),
            self.dups
        );
        //			self.remove(&hex::encode(content_packet.hash));  this will just start over if packets are in flight, so it needs a delay
        let mut sha256 = Sha256::new();
        copy(&mut self.file, &mut sha256)?;
        let hash: [u8; 256 / 8] = sha256
            .finalize()
            .as_slice()
            .try_into()
            .expect("Wrong Length");
        println!("verified hash {}", &hex::encode(&hash));
        std::assert_eq!(hash, self.hash);
        Ok(())
    }
    fn request_missing_or_next(&mut self, socket: &UdpSocket, src: &SocketAddr) {
        if self.next_missing > self.highest_seen {
            self.next_missing = 0;
        }
        while {
            self.next_missing += 1;
            self.next_missing %= blocks(self.len);
            self.bitmap.get(self.next_missing as usize).unwrap()
        } {}
        if self.next_missing > self.highest_seen {
            // nothing missing
            if self.lastreq + 1 >= blocks(self.len) {
                // on the tail, dont dup the window
                return;
            }
            self.lastreq += 1; // just increase window
            self.next_missing = self.lastreq;
        }
        let mut request_packet = RequestPacket {
            offset: 0,
            hash: self.hash,
        };
        request_packet.offset = self.next_missing;
        println!("requesting block {:>6}", request_packet.offset);
        let encoded: Vec<u8> = bincode::serialize(&request_packet).unwrap();
        socket.send_to(&encoded[..], &src).expect("cant send_to");
        self.requested += 1;
    }
}

#[repr(C)]
//#[derive(Copy,Clone)]
#[derive(Debug)]
struct ContentPacket {
    len: u64,
    offset: u64,
    hash: [u8; 256 / 8],
    data: [u8; ContentPacket::block_size() as usize], // serde had a strange 32 byte limit.  also serde would not be a portable network protocol format.
}

impl fmt::Display for ContentPacket {
 fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "just an excuse to use Display")
    }
}

impl ContentPacket {
    const fn block_size() -> u64 {
        1___0___2___4 // pointless use of Rust underline feature
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RequestPacket {
    offset: u64,
    hash: [u8; 256 / 8],
}

fn main() -> Result<(), std::io::Error>  {
    let args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        send(&args[1], &args[2])?;
    } else {
        receive()?;
    }
    Ok(())
}

fn send(pathname: &String, host: &String) -> Result<(), std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::new(5, 0)))?;
    let mut file = File::open(pathname)?;
    let metadata = fs::metadata(&pathname)?;
    let buffer = [0; ContentPacket::block_size() as usize]; // vec![0; 32 as usize];
    let mut started = false;

    fn send_block (
        mut content_packet: ContentPacket,
        host: &String,
        socket: &UdpSocket,
        file: &File,
    ) -> Result<(), std::io::Error>  {
        file.read_at(
            &mut content_packet.data,
            content_packet.offset * ContentPacket::block_size(),
        )?;
        let encoded: [u8; std::mem::size_of::<ContentPacket>()] =
            unsafe { transmute(content_packet) };
        socket.send_to(&encoded[..], host).expect("cant send_to");
        Ok(())
    }

    let mut sha256 = Sha256::new();
    copy(&mut file, &mut sha256)?;
    let hash = sha256
        .finalize()
        .as_slice()
        .try_into()
        .expect("wrong length");
    loop {
        if !started {
            let content_packet = ContentPacket {
                len: metadata.len(),
                offset: 0,
                hash: hash,
                data: buffer,
            };
            started = true;
            // excuse to support Debug and Display 
            println!("sample content packet: {:?}",content_packet);
            println!("content packet: {}",content_packet);
            send_block(content_packet, host, &socket, &file)?;
        } 
        let mut buf = [0; std::mem::size_of::<ContentPacket>()];
        match socket.recv_from(&mut buf) {
            Ok(_r) => true,
            Err(_e) => {
                started = false;
                println!("stalled, bumping");
                continue;
            }
        };
        let req: RequestPacket = bincode::deserialize(&buf).unwrap();
        if req.offset == !0 {
            println!("sent!");
            break;
        }
        println!("sending block: {}", req.offset);
        let content_packet = ContentPacket {
            len: metadata.len(),
            offset: req.offset,
            hash: hash,
            data: buffer,
        };
        send_block(content_packet, host, &socket, &file)?;
    }
    Ok(())
}

fn blocks(len: u64) -> u64 {
    return (len + ContentPacket::block_size() - 1) / ContentPacket::block_size();
}

fn receive() -> Result<(), std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:34254")?;
    use std::collections::HashMap;
    let mut inbound_states = HashMap::new();
    loop {
        let mut buf = [0; std::mem::size_of::<ContentPacket>()]; //	[0; ::std::mem::size_of::ContentPacket];
        let (_amt, src) = socket.recv_from(&mut buf).expect("socket error");
        let content_packet: ContentPacket = unsafe { transmute(buf) };
        println!("received block: {:>7}", content_packet.offset);

        if !inbound_states.contains_key(&content_packet.hash) {
            inbound_states.insert(content_packet.hash, InboundState::new(&content_packet)?);
        }
        inbound_states
            .get_mut(&content_packet.hash)
            .unwrap()
            .handle_content_packet(&content_packet, &socket, &src)?;
    }
}
