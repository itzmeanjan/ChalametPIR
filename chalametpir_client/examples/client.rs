use std::error::Error;

use chalametpir_client::{Client, SEED_BYTE_LEN};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SERVER_IP: &str = "127.0.0.1";
const SERVER_PORT: u16 = 8080;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_address = format!("{}:{}", SERVER_IP, SERVER_PORT);

    let mut stream = TcpStream::connect(&server_address).await.expect("Failed to connect to PIR server");
    println!("Connected to PIR server @ {}", &server_address);

    // Receive seed from PIR server
    let mut seed_μ = [0u8; SEED_BYTE_LEN];
    stream.read_exact(&mut seed_μ).await?;

    // Receive hint from PIR server
    let mut hint_len_buf = [0u8; 4];
    stream.read_exact(&mut hint_len_buf).await?;

    let hint_len = u32::from_le_bytes(hint_len_buf) as usize;

    let mut hint_bytes = vec![0u8; hint_len];
    stream.read_exact(&mut hint_bytes).await?;

    // Receive Binary Fuse Filter parameters from PIR server
    let mut filter_len_buf = [0u8; 4];
    stream.read_exact(&mut filter_len_buf).await?;

    let filter_len = u32::from_le_bytes(filter_len_buf) as usize;

    let mut filter_param_bytes = vec![0u8; filter_len];
    stream.read_exact(&mut filter_param_bytes).await?;

    println!("Received setup data from PIR server");

    let mut client = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("PIR client setup failed");

    let key = b"banana";
    if let Ok(query) = client.query(key) {
        println!("Generated query for key: {:?}", key);

        // Send query to PIR server
        let query_len = query.len() as u32;
        stream.write_all(&query_len.to_le_bytes()).await?;
        stream.write_all(&query).await?;

        println!("Sent query of length {}B", query_len);

        // Receive response from PIR server
        let mut response_len_buf = [0u8; 4];
        stream.read_exact(&mut response_len_buf).await?;

        let response_len = u32::from_le_bytes(response_len_buf) as usize;

        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response).await?;

        println!("Received response of length {}B", response_len);

        if let Ok(value) = client.process_response(key, &response) {
            println!("Retrieved value: '{}'", String::from_utf8_lossy(&value));
        } else {
            println!("Failed to retrieve value.");
        }
    } else {
        println!("Failed to generate query.");
    }

    Ok(())
}
