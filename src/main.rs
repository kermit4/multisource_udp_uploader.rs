use bit_vec::BitVec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::env;
use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::copy;
use std::mem::transmute;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

struct InboundState {
    file: File,
    len: u64,
    hash: [u8; 256 / 8],
    blocks_remaining: u64,
    next_block: u64,
    requested: u64,
    bitmap: BitVec,
    hash_checked: bool,
    dups: u64,
    start_time: SystemTime,
}

impl fmt::Display for InboundState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "rem/next/dups: {}/{}/{} avg B/s: {}",
            self.blocks_remaining,
            self.next_block,
            self.dups,
            (self.len - self.blocks_remaining * block_size())
                / (self.start_time.elapsed().unwrap().as_secs() + 1),
        )
    }
}

impl InboundState {
    // upload done
    fn check_hash(&mut self) -> Result<(), std::io::Error> {
        // this could be processed as received to reduce latency, but that may miss bugs

        self.file.set_len(self.len)?;
        println!("{}", self);
        println!("received {} dups {}", &hex::encode(&self.hash), self.dups);
        //			self.remove(&hex::encode(content_packet.hash));  this will just start over if packets are in flight, so it needs a delay
        let mut sha256 = Sha256::new();
        copy(&mut self.file, &mut sha256)?;
        let hash: [u8; 256 / 8] = sha256
            .finalize()
            .as_slice()
            .try_into()
            .expect("Wrong Length");
        std::assert_eq!(hash, self.hash);
        println!("verified hash {}", &hex::encode(&hash));
        Ok(())
    }

    fn handle_content_packet(
        &mut self,
        content_packet: &ContentPacket,
        socket: &UdpSocket,
        src: &SocketAddr,
    ) -> Result<(), std::io::Error> {
            #[cfg(debug_assertions)]
        println!(
            "received {} window(est): {}",
            content_packet.offset,
            self.next_block - content_packet.offset
        );
        if self.bitmap.get(content_packet.offset as usize).unwrap() {
            self.dups += 1;
            println!("dup: {} dups: {} window(est): {}", content_packet.offset, self.dups
                ,
            self.next_block - content_packet.offset
                );
        } else {
            self.file
                .write_at(&content_packet.data, content_packet.offset * block_size())?;
            self.blocks_remaining -= 1;
            self.bitmap.set(content_packet.offset as usize, true);
        }
        let mut request_packet = RequestPacket {
            offset: !0,
            hash: self.hash,
        };
        while {
            #[cfg(debug_assertions)]
            println!("{}", self);
            if self.blocks_remaining == 0 {
                if !self.hash_checked {
                    self.check_hash()?;
                    self.hash_checked = true;
                    drop(&self.file); // free up a file descriptor
                }
            } else {
                request_packet.offset = self.next_block;
                //                println!("{}",self.bitmap.iter().position(|x| x == false ).unwrap());
                while {
                    self.next_block += 1;
                    self.next_block %= blocks(self.len);
                    self.bitmap.get(self.next_block as usize).unwrap()
                } {}
            }
            #[cfg(debug_assertions)]
            println!("requesting block {:>6}", request_packet.offset);
            let encoded: Vec<u8> = bincode::serialize(&request_packet).unwrap();
            socket.send_to(&encoded[..], &src).expect("cant send_to");
            self.requested += 1;
            (self.requested % 100) == 0
        } {}
        Ok(())
    }
}

#[repr(C)]
//#[derive(Copy,Clone)]
#[derive(Debug, Copy, Clone)]
struct ContentPacket {
    len: u64,
    offset: u64,
    hash: [u8; 256 / 8],
    data: [u8; block_size() as usize], // serde had a strange 32 byte limit.  also serde would not be a portable network protocol format.
}

const fn block_size() -> u64 {
    1___0___2___4 // pointless use of Rust underline feature
}
impl ContentPacket {
    fn new_inbound_state(&self) -> Result<InboundState, std::io::Error> {
        Ok(InboundState {
                file:  // File::create(
				OpenOptions::new().create(true).read(true).write(true)
                    .open(Path::new(&hex::encode(self.hash)))?,
                len: self.len,
                blocks_remaining: blocks(self.len),
                next_block: 1,
				hash_checked: false,
                hash: self.hash,
                requested: 0,
                bitmap: BitVec::from_elem(blocks(self.len) as usize, false),
                dups:0,
               start_time : SystemTime::now(),
            })
    }

    fn send(
        &mut self,
        host: &String,
        socket: &UdpSocket,
        file: &File,
    ) -> Result<(), std::io::Error> {
        file.read_at(&mut self.data, self.offset * block_size())?;
        let encoded: [u8; std::mem::size_of::<Self>()] = unsafe { transmute(*self) };
        socket.send_to(&encoded[..], host).expect("cant send_to");
        Ok(())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RequestPacket {
    offset: u64,
    hash: [u8; 256 / 8],
}

fn main() -> Result<(), std::io::Error> {
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
    socket.set_read_timeout(Some(Duration::new(1, 0)))?;
    let mut file = File::open(pathname)?;
    let metadata = fs::metadata(&pathname)?;
    let buffer = [0; block_size() as usize]; // vec![0; 32 as usize];
    let mut started = false;

    let mut sha256 = Sha256::new();
    copy(&mut file, &mut sha256)?;
    let hash = sha256
        .finalize()
        .as_slice()
        .try_into()
        .expect("wrong length");
    loop {
        let mut offset = 0;
        if started {
            let mut buf = [0; 1000];
            match socket.recv_from(&mut buf) {
                Ok(_r) => true,
                Err(_e) => {
                    started = false;
                    println!("stalled, bumping");
                    continue;
                }
            };
            let req: RequestPacket = bincode::deserialize(&buf).unwrap();
            offset = req.offset;
            if offset == !0 {
                println!("sent!");
                break;
            }
        }
        #[cfg(debug_assertions)]
        println!("sending block: {}", offset);
        ContentPacket {
            len: metadata.len(),
            offset: offset,
            hash: hash,
            data: buffer,
        }
        .send(host, &socket, &file)?;
        started = true;
    }
    Ok(())
}

fn blocks(len: u64) -> u64 {
    return (len + block_size() - 1) / block_size();
}

fn receive() -> Result<(), std::io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:34254")?;
    use std::collections::HashMap;
    let mut inbound_states = HashMap::new();
    //let mut encoded: Vec<u8> = Vec::new(); // attempt to udp nat hole punch
  //  encoded.push(1);
//    socket.send_to(&encoded[..], "3.139.163.145:33333").expect("cant send_to");
    loop {
        let mut buf = [0; std::mem::size_of::<ContentPacket>()]; //	[0; ::std::mem::size_of::ContentPacket];
        let (_amt, src) = socket.recv_from(&mut buf).expect("socket error");
        let content_packet: ContentPacket = unsafe { transmute(buf) };

        if !inbound_states.contains_key(&content_packet.hash) {
            inbound_states.insert(content_packet.hash, content_packet.new_inbound_state()?);
        }
        inbound_states
            .get_mut(&content_packet.hash)
            .unwrap()
            .handle_content_packet(&content_packet, &socket, &src)?;
    }
}
