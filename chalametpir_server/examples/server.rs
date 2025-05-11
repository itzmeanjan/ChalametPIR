use std::sync::Arc;
use std::{collections::HashMap, error::Error};

use chalametpir_server::{SEED_BYTE_LEN, Server};

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const ARITY_OF_BINARY_FUSE_FILTER: u32 = 3;
const HOST_IP: &str = "127.0.0.1";
const HOST_PORT: u16 = 8080;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_address = format!("{}:{}", HOST_IP, HOST_PORT);

    let listener = TcpListener::bind(&server_address).await.expect("Failed to setup TCP listener for PIR server");
    println!("PIR Server listening @ {}", &server_address);

    let mut rng = ChaCha8Rng::from_os_rng();
    let mut seed_μ = [0u8; SEED_BYTE_LEN];
    rng.fill_bytes(&mut seed_μ);

    let mut db: HashMap<&[u8], &[u8]> = HashMap::new();
    db.insert(b"apple", b"red");
    db.insert(b"banana", b"yellow");
    db.insert(b"grape", b"purple");
    db.insert(b"orange", b"orange");
    db.insert(b"lemon", b"yellow");
    db.insert(b"blueberry", b"blue");
    db.insert(b"kiwi", b"brown");
    db.insert(b"watermelon", b"green");
    db.insert(b"strawberry", b"red");
    db.insert(b"peach", b"pink");
    db.insert(b"pineapple", b"yellow");
    db.insert(b"cherry", b"red");
    db.insert(b"avocado", b"green");
    db.insert(b"plum", b"purple");
    db.insert(b"cantaloupe", b"orange");

    let (server, hint_bytes, filter_param_bytes) = Server::setup::<ARITY_OF_BINARY_FUSE_FILTER>(&seed_μ, db).expect("PIR server setup failed");

    let arced_server = Arc::new(server);
    let arced_hint = Arc::new(hint_bytes);
    let arced_filter_param = Arc::new(filter_param_bytes);

    loop {
        let (mut stream, _) = listener.accept().await?;
        let peer_address = stream.peer_addr().unwrap();
        println!("New connection from PIR client @ {}", peer_address);

        // Cheap cloning, because they are Arced !
        let cloned_server = arced_server.clone();
        let cloned_hint = arced_hint.clone();
        let cloned_filter_param = arced_filter_param.clone();

        tokio::spawn(async move {
            // Send seed to PIR client
            stream.write_all(&seed_μ).await.unwrap();

            // Send hint to PIR client
            let hint_len = cloned_hint.len() as u32;
            stream.write_all(&hint_len.to_le_bytes()).await.unwrap();
            stream.write_all(&cloned_hint).await.unwrap();

            // Send Binary Fuse Filter parameters to PIR client
            let filter_len = cloned_filter_param.len() as u32;
            stream.write_all(&filter_len.to_le_bytes()).await.unwrap();
            stream.write_all(&cloned_filter_param).await.unwrap();

            println!("Sent setup data to PIR client @ {}", peer_address);

            // Receive query from PIR client
            let mut query_len_buf = [0u8; 4];
            stream.read_exact(&mut query_len_buf).await.unwrap();

            let query_len = u32::from_le_bytes(query_len_buf) as usize;

            let mut query = vec![0u8; query_len];
            stream.read_exact(&mut query).await.unwrap();

            println!("Received query of length {}B, from PIR client @ {}", query_len, peer_address);
            let response = cloned_server.respond(&query).expect("PIR server failed to respond");

            // Send response to PIR client
            let response_len = response.len() as u32;
            stream.write_all(&response_len.to_le_bytes()).await.unwrap();
            stream.write_all(&response).await.unwrap();

            println!("Sent response of length {}B, to PIR client @ {}", response_len, peer_address);
        });
    }
}
