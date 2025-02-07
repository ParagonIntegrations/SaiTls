#![no_std]
#![no_main]

use embedded_nal_tcp_stack as nal;
use nal::{IpAddr, Ipv4Addr, SocketAddr, TcpStack};
use SaiTLS::tls::TlsSocket;
use smoltcp as net;
use rand_core::{CryptoRng, Error, OsRng, RngCore};
use SaiTLS::tcp_stack::NetworkStack;
use SaiTLS::TlsRng;


use rust_mqtt::client::client::MqttClient;
use rust_mqtt::client::client_config::{ClientConfig, MqttVersion};
use rust_mqtt::packet::v5::reason_codes::ReasonCode;
use rust_mqtt::utils::rng_generator::CountingRng;

use embassy_executor::{task, Spawner};

const BUFFER_SIZE: usize = 1024;

#[test]
async fn test_tls() {
    let spawner = Spawner::for_current_executor().await;
}

#[test]
async fn mqtt() {
    let mut rng = NelisRng {rng:OsRng::default()};

    // Typical TCP socket from smoltcp
    let mut tx_storage = [0; 4096];
    let mut rx_storage = [0; 4096];
    let tx_buffer = net::socket::TcpSocketBuffer::new(&mut tx_storage[..]);
    let rx_buffer = net::socket::TcpSocketBuffer::new(&mut rx_storage[..]);
    let mut tcp_socket = net::socket::TcpSocket::new(rx_buffer, tx_buffer);

    // TLS socket constructor
    let tls_socket = TlsSocket::new(
        tcp_socket,
        &mut rng,   // Assume rng is from a struct that implements TlsRng
        None
    );

    // Prepare a socket set for TLS sockets
    let mut tls_socket_entries: [_; 1] = Default::default();
    let mut tls_socket_set = SaiTLS::set::TlsSocketSet::new(
        &mut tls_socket_entries[..]
    );
    // // Use TLS socket set & handle to access TLS socket
    let tls_handle = tls_socket_set.add(tls_socket);
    // {
    //     let mut tls_socket = tls_socket_set.get(tls_handle);
    //     /* Socket manipulations */
    //
    // }
    let tls_stack = NetworkStack::new(tls_socket_set);
    let remote_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(137,135,83,217)), 8883);
    tls_stack.connect(tls_handle, remote_endpoint).expect("TODO: panic message");
    println!("Successfully connected");

    // send message
    let mut send_buffer = [0_u8; BUFFER_SIZE];
    let mut receive_buffer = [0_u8; BUFFER_SIZE];
    let client_id_str = "test";
    let mut mqtt_client_config: ClientConfig<'_, 5, CountingRng> =
        ClientConfig::new(MqttVersion::MQTTv5, CountingRng(12345));
    mqtt_client_config.add_client_id(
        client_id_str
    );
    let mut mqtt_client = MqttClient::new(
        tls_stack,
        &mut send_buffer,
        BUFFER_SIZE,
        &mut receive_buffer,
        BUFFER_SIZE,
        mqtt_client_config,
    );
    mqtt_client.connect_to_broker().await.unwrap();
    // mqtt_client
    //     .subscribe_to_topic("esp32_test_configuration")
    //     .await
    //     .unwrap();


    let topic = "esp32_test_topic".to_owned();
    let payload = "abc".as_bytes().to_vec();
    loop {
        mqtt_client
            .send_message(
                &topic,
                &payload,
                rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1,
                false,
            )
            .await
            .unwrap();

        // Timer::after_millis(5000).await;
    }


}

struct NelisRng {
    rng: OsRng
}

impl RngCore for NelisRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for NelisRng {}

impl TlsRng for NelisRng {

}