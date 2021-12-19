extern crate af_packet;
extern crate num_cpus;

use std::env;
use std::thread;

#[cfg(not(feature = "async-tokio"))]
fn worker(idx: usize, interface: String) {
    let mut ring = af_packet::rx::Ring::from_if_name(&interface)
        .map_err(|err| eprintln!("start worker #{} failure: {}", idx, err))
        .unwrap();
    loop {
        let block = ring.recv_block(); //THIS WILL BLOCK
        for pack in block.into_raw_packets_iter() {
            let _payload = pack.payload();

            //do something
        }
        // the current block is marked as consumed during a iterator drop
    }
}

#[cfg(feature = "async-tokio")]
fn worker(idx: usize, interface: String) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut ring = af_packet::rx::AsyncRing::from_if_name(&interface)
            .map_err(|err| eprintln!("start worker #{} failure: {}", idx, err))
            .unwrap();
        loop {
            match ring.recv_block().await {
                Ok(block) => {
                    for pack in block.into_raw_packets_iter() {
                        let _payload = pack.payload();

                        //do something
                    }
                    // the current block is marked as consumed during a iterator drop
                }
                Err(_err) => {
                    //do something
                }
            }
        }
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    for idx in 0..num_cpus::get() {
        let interface = args[1].clone();
        thread::spawn(move || worker(idx, interface));
    }
    //keep main thread alive
    loop {
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
