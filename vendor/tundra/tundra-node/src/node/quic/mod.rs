use crate::{
    node::identity::Identity,
    pinning::{CertPins, PeerClientVerifier, PeerServerVerifier},
};
use anyhow::Context;
use quinn::{
    Endpoint, EndpointConfig, MtuDiscoveryConfig, TokioRuntime, TransportConfig, VarInt,
    congestion::CubicConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::crypto::CryptoProvider;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tundra_common::wire::ALPN_TUNNEL;

pub mod conn;
pub mod handshake;
pub mod registry;

pub const KEEPALIVE: Duration = Duration::from_secs(15);
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
pub const MTU_UPPER_BOUND: u16 = 1500;
pub const STREAM_RECEIVE_WINDOW: u32 = 1024 * 1024;

pub const TARGET_STREAM_RATE: u64 = 25 * 1024 * 1024;
pub const MIN_STREAM_WINDOW: u32 = 256 * 1024;
pub const MAX_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
pub const CONN_WINDOW_STREAMS: u32 = 8;
pub const DATAGRAM_SEND_BUFFER: usize = 2 * 1024 * 1024;
pub const DATAGRAM_RECEIVE_BUFFER: usize = 2 * 1024 * 1024;
pub const MAX_CONCURRENT_BIDI_STREAMS: u32 = 4096;

pub const MAX_INCOMING_HANDSHAKES: usize = 64;
pub const INCOMING_BUFFER_TOTAL: u64 = 4 * 1024 * 1024;

pub fn stream_window_for(rtt: Option<Duration>) -> u32 {
    let Some(rtt) = rtt else {
        return STREAM_RECEIVE_WINDOW;
    };

    let ideal = (TARGET_STREAM_RATE as f64 * rtt.as_secs_f64()) as u64;
    ideal.clamp(u64::from(MIN_STREAM_WINDOW), u64::from(MAX_STREAM_WINDOW)) as u32
}

pub fn transport_config(rtt: Option<Duration>) -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEPALIVE));
    transport.max_idle_timeout(Some(
        MAX_IDLE_TIMEOUT
            .try_into()
            .expect("failed to convert the idle timeout to a varint"),
    ));

    let mut mtu = MtuDiscoveryConfig::default();
    mtu.upper_bound(MTU_UPPER_BOUND);
    transport.mtu_discovery_config(Some(mtu));

    let stream_window = stream_window_for(rtt);
    transport.stream_receive_window(stream_window.into());
    transport.receive_window((stream_window * CONN_WINDOW_STREAMS).into());
    transport.datagram_send_buffer_size(DATAGRAM_SEND_BUFFER);
    transport.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER));
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));

    // Cubic, deliberately. quinn's only BBR is the experimental quiche-derived v1 port,
    // and on a netem 40ms path it measured 0.6 MB/s against cubic's 22.9 MB/s with zero
    // loss, and 0.3 vs 1.1 MB/s at 1% loss. No BBRv3
    // implementation exists for quinn; revisit if one lands upstream.
    transport.congestion_controller_factory(Arc::new(CubicConfig::default()));

    transport
}

pub fn server_config(
    identity: &Identity,
    pins: Arc<dyn CertPins>,
    provider: Arc<CryptoProvider>,
    rtt: Option<Duration>,
) -> Result<quinn::ServerConfig, anyhow::Error> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(PeerClientVerifier::new(pins, provider)))
        .with_single_cert(identity.chain(), identity.key())
        .context("failed to install the node certificate")?;
    tls.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(Arc::new(transport_config(rtt)));
    config.migration(false);
    config.max_incoming(MAX_INCOMING_HANDSHAKES);
    config.incoming_buffer_size_total(INCOMING_BUFFER_TOTAL);

    Ok(config)
}

pub fn client_config(
    identity: &Identity,
    pins: Arc<dyn CertPins>,
    provider: Arc<CryptoProvider>,
    expected: uuid::Uuid,
    rtt: Option<Duration>,
) -> Result<quinn::ClientConfig, anyhow::Error> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PeerServerVerifier::new(
            expected, pins, provider,
        )))
        .with_client_auth_cert(identity.chain(), identity.key())
        .context("failed to install the node certificate for dialing")?;
    tls.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];

    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(Arc::new(transport_config(rtt)));

    Ok(config)
}

pub fn endpoint(bind: SocketAddr, server: quinn::ServerConfig) -> Result<Endpoint, anyhow::Error> {
    let socket = std::net::UdpSocket::bind(bind).context(format!("failed to bind {bind}"))?;
    socket.set_nonblocking(true)?;

    Endpoint::new(
        EndpointConfig::default(),
        Some(server),
        socket,
        Arc::new(TokioRuntime),
    )
    .context("failed to create the quic endpoint")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transport_limits_match_the_documented_caps() {
        // TransportConfig has no getters, so assert the values that feed it instead
        assert_eq!(KEEPALIVE, Duration::from_secs(15));
        assert_eq!(MAX_IDLE_TIMEOUT, Duration::from_secs(45));
        assert!(KEEPALIVE * 2 < MAX_IDLE_TIMEOUT);
        assert_eq!(STREAM_RECEIVE_WINDOW, 1024 * 1024);
        assert_eq!(DATAGRAM_SEND_BUFFER, 2 * 1024 * 1024);
        assert_eq!(DATAGRAM_RECEIVE_BUFFER, 2 * 1024 * 1024);
        assert_eq!(MTU_UPPER_BOUND, 1500);
        const { assert!(MAX_INCOMING_HANDSHAKES <= 256) };

        let _ = transport_config(None);
    }

    #[test]
    fn windows_scale_with_the_path_rtt_between_the_clamps() {
        assert_eq!(stream_window_for(None), STREAM_RECEIVE_WINDOW);
        assert_eq!(
            stream_window_for(Some(Duration::from_micros(300))),
            MIN_STREAM_WINDOW
        );
        assert_eq!(
            stream_window_for(Some(Duration::from_millis(80))),
            2 * 1024 * 1024
        );
        assert_eq!(
            stream_window_for(Some(Duration::from_secs(2))),
            MAX_STREAM_WINDOW
        );
        // the connection window never overflows the varint conversion
        const { assert!(MAX_STREAM_WINDOW as u64 * CONN_WINDOW_STREAMS as u64 <= u32::MAX as u64) };
    }
}
