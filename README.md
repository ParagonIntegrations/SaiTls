# SaiTLS

`[no-std]` Client & Server side TLS implementation on top of smoltcp, using allocator.

## Features
This crate supports these algorithms:
- Cipher suites:
  - TLS_AES_128_GCM_SHA256
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_AES_128_CCM_SHA256
- Ecliptic curves:
  - X25519
  - secp256r1 (NIST P-256)
- Digital signature algorithms:
  - ecdsa_secp256r1_sha256
  - ed25519
  - RSASSA-PKCS1-v1_5 algorithms
  - RSASSA-PSS algorithms

Implementation of all algorithms (except x25519 & ed25519) are directly sourced from the [RustCrypto](https://github.com/RustCrypto) project.

Implementation of x25519 & ed25519 algorithms are directly sourced from the [dalek-cryptography](https://github.com/dalek-cryptography) project.

Algorithms not listed above are __NOT__ supported. Using certificates with unsupported algorithms will cause handshake/communication failure.

This crate supports these handshake features:
- Certificate verification, with a single self-signed certificate
- (Client) Client certificate verification, if requested by remote server
- (Server) Send Client Certificate Request to remote client

These handshake features are __NOT__ supported:
- HelloRetryRequest
- Pre-shared key & New session ticket
- Early data
- 0-RTT handshake
- Verification of non-self-signed certificates, including certificate chain

## TLS Socket
To create a TLS socket, the following items are needed:
- TCP Socket from smoltcp
- Random number generator (cryptographically secure RNG is recommended)
- (Optional) Client certificates in x509 certificate & the associated private key

The RNG requires the `TlsRng` trait to be implemented, which further include these traits:
- `RngCore` from rand_core
- `CryptoRng` from rand_core

TLS socket can be instantiated by the following lines of code:
```rust
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
```

## Socket Storage & Access
Similar to smoltcp, a `TlsSocketSet` is needed to hold the sockets.
Use `TlsSocketHandle` to gain access to a TLS Socket indirectly.
```rust
    // Prepare a socket set for TLS sockets
    let mut tls_socket_entries: [_; 1] = Default::default();
    let mut tls_socket_set = SaiTLS::set::TlsSocketSet::new(
        &mut tls_socket_entries[..]
    );
    // Use TLS socket set & handle to access TLS socket
    let tls_handle = tls_socket_set.add(tls_socket);
    {
        let mut tls_socket = tls_socket_set.get(tls_handle);
        /* Socket manipulations */
    }
```

## Polling
The `poll(..)` function substitutes the `EthernetInterface.poll(..)` function in smoltcp.
```rust
    SaiTLS::poll(
        Some(&mut smoltcp_sockets),     // Optional socket set from smoltcp
        &mut tls_socket_set,
        &mut ethernet_interface,
        smoltcp::time::Instant::from_millis(time)
    );
```
Sockets in either `smoltcp_sockets` or `tls_socket_set` will be updated.

## Authentication on SaiTLS side
If necessary, SaiTLS will send X.509 certificate to the remote side, designated in the constructor. This requires X.509 certificate and its associated private key to be loaded onto the socket. A X.509 self-signed certificate and the signature private key can be generated by OpenSSL using the following command:
```
openssl req -x509 -newkey rsa:1024 -sha256 -nodes -keyout key.der -out cert.der -days 30 -outform DER
```
This will generate a self-signed certificate in DER format as `cert.der`, signed by an RSA key with 1024 bits as `key.der`. The certificate supplied to SaiTLS must be in DER format.

The `include_bytes!()` Rust macro can load the DER certificate as a binary slice.
Private/Secrete key needs to be instantiated by the corresponding RustCrypto/Dalek library. The following is an example of loading `cert.der` and `key.der` into the constructor of `TLSSocket`.

```Rust
// This line includes the certificate in DER format
const CERT: &'static [u8] = include_bytes!( `<path-to-certificate>` );
// These lines contains components of the RSA private key
const PRIVATE_KEY_MOD: &'static [u8] = ... ;
const PUBLIC_KEY_EXP: &'static [u8] = &[ 0x01, 0x00, 0x01 ];
const PRIVATE_KEY_EXP: &'static [u8] = ... ;
const CLIENT_PRIME_1: &'static [u8] = ... ;
const CLIENT_PRIME_2: &'static [u8] = ... ;
```
The exact values of these constants can be found by printing out the content using OpenSSL, such as the following command.
```
openssl rsa -in key.der -text
```
The private key can then be assembled as such:
```Rust
let mut prime_vec = alloc::vec::Vec::new();
prime_vec.push(rsa::BigUint::from_bytes_be(&CLIENT_PRIME_1));
prime_vec.push(rsa::BigUint::from_bytes_be(&CLIENT_PRIME_2));

let rsa_key = rsa::RSAPrivateKey::from_components(
    rsa::BigUint::from_bytes_be(CLIENT_PRIVATE_KEY_MOD),
    rsa::BigUint::from_bytes_be(CLIENT_PUBLIC_KEY_EXP),
    rsa::BigUint::from_bytes_be(CLIENT_PRIVATE_KEY_EXP),
    prime_vec
);
```
Finally, the private key and the certificate are loaded onto the socket.
```Rust
let mut tls_socket = TlsSocket::new(
    tcp_socket,
    &mut rng_struct,
    Some((cert_private_key, alloc::vec![CLIENT_CERT]))
);
```
Loading more than 1 certificate (i.e. a certificate chain) is experimental. Use at your own risk!

Note that the remote side may not necessarily accept the self-signed certificate. It is entirely up to the remote side to accept or reject your provided certificate. Designation of trusted files might be helpful (e.g. the `--trustfile` option in Ncat).

## Feature `nal_tcp_stack`
Implements `TcpStack` in embedded-nal (v0.1.0) for `TlsSocket`. This disguises `TlsSocket` as just another TCP socket, potentially useful for implementating application layer protocols (e.g. MQTT in minimq).

Usage:
```Rust
let tls_socket_set = SaiTLS::set::TlsSocketSet::new( .. );
let tls_stack = NetworkStack::new(tls_socket_set);
```
