use crate::client::{LocalSendClient, TlsTrustPolicy};
use crate::core::device::{get_device_model, get_device_type, get_local_ip};
use crate::crypto::generate_fingerprint;
use crate::discovery::Discovery;
use crate::error::LocalSendError;
use crate::protocol::{
    AnnouncementMessage, DEFAULT_MULTICAST_ADDRESS, DEFAULT_MULTICAST_PORT, DeviceInfo,
    PROTOCOL_VERSION, Protocol,
};
use if_addrs::{IfAddr, get_if_addrs};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;

pub type Result<T> = std::result::Result<T, LocalSendError>;

#[derive(Clone)]
pub struct MulticastDiscovery {
    local_device: DeviceInfo,
    sockets: Vec<Arc<UdpSocket>>,
    running: Arc<AtomicBool>,
    tx: Option<broadcast::Sender<DeviceInfo>>,
}

impl MulticastDiscovery {
    pub fn new(alias: String, port: u16, protocol: Protocol) -> Result<Self> {
        let device = DeviceInfo {
            alias,
            version: PROTOCOL_VERSION.to_string(),
            device_model: Some(get_device_model()),
            device_type: Some(get_device_type()),
            fingerprint: generate_fingerprint(),
            port,
            protocol,
            download: false,
            ip: None,
        };

        Ok(Self::new_with_device(device))
    }

    pub fn new_with_device(device: DeviceInfo) -> Self {
        let (tx, _rx) = broadcast::channel(100);
        Self {
            local_device: device,
            sockets: Vec::new(),
            running: Arc::new(AtomicBool::new(false)),
            tx: Some(tx),
        }
    }
}

#[async_trait::async_trait]
impl Discovery for MulticastDiscovery {
    async fn start(&mut self) -> std::result::Result<(), LocalSendError> {
        if self.running.load(Ordering::Relaxed) {
            return Err(LocalSendError::network("Discovery already running"));
        }

        let bind_addr: SocketAddr = format!("0.0.0.0:{}", DEFAULT_MULTICAST_PORT).parse()?;
        let sockets = Self::multicast_interfaces()?
            .into_iter()
            .map(|interface| create_reusable_udp_socket(&bind_addr, interface))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<_>>();

        self.sockets = sockets.clone();
        self.running.store(true, Ordering::Relaxed);

        for socket in sockets {
            let tx = self.tx.as_ref().unwrap().clone();
            let local_fingerprint = self.local_device.fingerprint.clone();
            let running = self.running.clone();
            let local_device = self.local_device.clone();

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];

                while running.load(Ordering::Relaxed) {
                    match tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
                        .await
                    {
                        Ok(Ok((len, src))) => {
                            if len > 0 {
                                let msg = match String::from_utf8(buf[..len].to_vec()) {
                                    Ok(s) => s,
                                    Err(_) => continue,
                                };

                                if let Ok(announcement) =
                                    serde_json::from_str::<AnnouncementMessage>(&msg)
                                {
                                    if announcement.fingerprint == local_fingerprint {
                                        continue;
                                    }

                                    let device = DeviceInfo {
                                        alias: announcement.alias.clone(),
                                        version: announcement.version.clone(),
                                        device_model: announcement.device_model.clone(),
                                        device_type: announcement.device_type,
                                        fingerprint: announcement.fingerprint.clone(),
                                        port: announcement.port,
                                        protocol: announcement.protocol,
                                        download: announcement.download,
                                        ip: Some(src.ip().to_string()),
                                    };

                                    let is_announcement = announcement.announce
                                        || announcement.announcement.unwrap_or(false);
                                    let _ = tx.send(device.clone());

                                    if is_announcement {
                                        let local_device = local_device.clone();
                                        let socket = socket.clone();

                                        tokio::spawn(async move {
                                            Self::respond_to_announcement(
                                                &device,
                                                &local_device,
                                                &socket,
                                            )
                                            .await;
                                        });
                                    }
                                }
                            }
                        }
                        Ok(Err(_)) | Err(_) => continue,
                    }
                }
            });
        }

        Ok(())
    }

    fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.sockets.clear();
        self.tx = None;
    }

    async fn announce_presence(&self) -> std::result::Result<(), LocalSendError> {
        if self.sockets.is_empty() {
            return Err(LocalSendError::network("Discovery not started"));
        }

        let announcement = AnnouncementMessage {
            alias: self.local_device.alias.clone(),
            version: self.local_device.version.clone(),
            device_model: self.local_device.device_model.clone(),
            device_type: self.local_device.device_type,
            fingerprint: self.local_device.fingerprint.clone(),
            port: self.local_device.port,
            protocol: self.local_device.protocol,
            download: self.local_device.download,
            announce: true,
            announcement: Some(true),
        };

        let msg = serde_json::to_string(&announcement)?;
        let buf = msg.as_bytes();
        let multicast_addr: SocketAddr =
            format!("{}:{}", DEFAULT_MULTICAST_ADDRESS, DEFAULT_MULTICAST_PORT).parse()?;

        // Send announcement multiple times with delays to improve reliability
        let delays = [100, 500, 2000];
        for delay in delays {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            for socket in &self.sockets {
                socket.send_to(buf, &multicast_addr).await?;
            }
        }

        Ok(())
    }

    fn on_discovered<F>(&mut self, callback: F)
    where
        F: Fn(DeviceInfo) + Send + Sync + 'static,
    {
        let tx = if let Some(ref t) = self.tx {
            t.clone()
        } else {
            return;
        };

        tokio::spawn(async move {
            let mut rx = tx.subscribe();
            while let Ok(device) = rx.recv().await {
                callback(device);
            }
        });
    }

    fn get_known_devices(&self) -> Vec<DeviceInfo> {
        vec![]
    }
}

impl MulticastDiscovery {
    fn multicast_interfaces() -> Result<Vec<Ipv4Addr>> {
        let addresses = get_if_addrs()
            .map_err(|error| {
                LocalSendError::network(format!("Failed to list interfaces: {error}"))
            })?
            .into_iter()
            .filter(|interface| !interface.is_loopback())
            .filter_map(|interface| match interface.addr {
                IfAddr::V4(address) => Some((address.ip, address.netmask)),
                IfAddr::V6(_) => None,
            });
        let addresses = addresses.collect::<Vec<_>>();
        let primary = get_local_ip().ok();
        let mut interfaces = Self::multicast_interfaces_from(addresses.iter().copied(), primary);

        if interfaces.is_empty() && primary.is_some() {
            interfaces = Self::multicast_interfaces_from(addresses, None);
        }

        if interfaces.is_empty() {
            Ok(vec![Ipv4Addr::UNSPECIFIED])
        } else {
            Ok(interfaces)
        }
    }

    fn multicast_interfaces_from(
        addresses: impl IntoIterator<Item = (Ipv4Addr, Ipv4Addr)>,
        primary: Option<Ipv4Addr>,
    ) -> Vec<Ipv4Addr> {
        addresses
            .into_iter()
            .filter(|(address, _)| !address.is_unspecified() && !address.is_loopback())
            .filter(|(address, netmask)| {
                primary.is_none_or(|primary| Self::same_subnet(*address, primary, *netmask))
            })
            .map(|(address, _)| address)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn same_subnet(address: Ipv4Addr, primary: Ipv4Addr, netmask: Ipv4Addr) -> bool {
        let netmask = u32::from_be_bytes(netmask.octets());
        u32::from_be_bytes(address.octets()) & netmask
            == u32::from_be_bytes(primary.octets()) & netmask
    }

    fn client_for_announcement(
        local_device: DeviceInfo,
        target_device: &DeviceInfo,
    ) -> Result<LocalSendClient> {
        match target_device.protocol {
            Protocol::Http => Ok(LocalSendClient::new(local_device)),
            Protocol::Https => LocalSendClient::with_trust_policy(
                local_device,
                TlsTrustPolicy::PinnedFingerprint(target_device.fingerprint.clone()),
            ),
        }
    }

    pub async fn scan(
        &mut self,
        duration: Duration,
        devices: Arc<RwLock<Vec<DeviceInfo>>>,
    ) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            self.start().await?;
        }

        // Register a callback to update the devices list during the scan
        let devices_clone = devices.clone();
        self.on_discovered(move |device| {
            let mut guard = devices_clone.write().unwrap();
            if !guard.iter().any(|d| d.fingerprint == device.fingerprint) {
                guard.push(device);
            }
        });

        // Clear devices
        devices.write().unwrap().clear();

        // Announce
        self.announce_presence().await?;

        // Wait for responses
        tokio::time::sleep(duration).await;

        Ok(())
    }

    async fn respond_to_announcement(
        target_device: &DeviceInfo,
        local_device: &DeviceInfo,
        socket: &UdpSocket,
    ) {
        tracing::debug!(
            "Responding to announcement from {} ({:?})",
            target_device.alias,
            target_device.ip
        );

        // The discovery announcement contains the peer's certificate fingerprint.
        // Use it for HTTPS registration instead of system CA verification.
        match Self::client_for_announcement(local_device.clone(), target_device) {
            Ok(client) => match client.register(target_device).await {
                Ok(_) => {
                    tracing::debug!(
                        "Successfully registered with {} via HTTP",
                        target_device.alias
                    );
                    return;
                }
                Err(error) => {
                    // If HTTP failed, we just fall back to UDP. This is common if the other device
                    // has a strict firewall or if we couldn't parse their response.
                    // It's not a critical error.
                    tracing::debug!(
                        "HTTP registration failed ({}), falling back to UDP...",
                        error
                    );
                }
            },
            Err(error) => {
                tracing::debug!(
                    "Could not configure pinned registration ({}), falling back to UDP...",
                    error
                );
            }
        }

        // Fallback: Send UDP response
        let announcement = AnnouncementMessage {
            alias: local_device.alias.clone(),
            version: local_device.version.clone(),
            device_model: local_device.device_model.clone(),
            device_type: local_device.device_type,
            fingerprint: local_device.fingerprint.clone(),
            port: local_device.port,
            protocol: local_device.protocol,
            download: local_device.download,
            announce: false,
            announcement: Some(false),
        };

        if let Ok(msg) = serde_json::to_string(&announcement) {
            let buf = msg.as_bytes();
            let multicast_addr_str =
                format!("{}:{}", DEFAULT_MULTICAST_ADDRESS, DEFAULT_MULTICAST_PORT);
            if let Ok(multicast_addr) = multicast_addr_str.parse::<SocketAddr>() {
                if let Err(e) = socket.send_to(buf, &multicast_addr).await {
                    tracing::debug!("Failed to send UDP fallback response: {}", e);
                } else {
                    tracing::debug!("Sent UDP fallback response to multicast group");
                }
            }
        }
    }
}

/// Creates a UDP socket with port reuse enabled.
///
/// This is critical for LocalSend discovery because:
/// 1. The protocol uses a fixed multicast port (53317).
/// 2. Multiple instances (e.g., a background receiver and a short-lived discovery command)
///    need to join the same multicast group simultaneously.
///
/// By enabling SO_REUSEADDR (and SO_REUSEPORT on Unix), the OS allows multiple
/// processes to bind to the same UDP port. For multicast traffic, the OS will
/// clone incoming packets and deliver them to all participating sockets.
fn create_reusable_udp_socket(bind_addr: &SocketAddr, interface: Ipv4Addr) -> Result<UdpSocket> {
    let domain = if bind_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP))
        .map_err(|e| LocalSendError::network(format!("Failed to create socket: {}", e)))?;

    // Enable address reuse (supported on most platforms including Windows)
    socket
        .set_reuse_address(true)
        .map_err(|e| LocalSendError::network(format!("Failed to set reuse_address: {}", e)))?;

    // Enable port reuse on Unix platforms to allow multiple processes to bind exactly to the same port
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket
        .set_reuse_port(true)
        .map_err(|e| LocalSendError::network(format!("Failed to set reuse_port: {}", e)))?;

    socket
        .bind(&(*bind_addr).into())
        .map_err(|e| LocalSendError::network(format!("Failed to bind to {}: {}", bind_addr, e)))?;

    let multicast_addr = DEFAULT_MULTICAST_ADDRESS
        .parse::<Ipv4Addr>()
        .map_err(|error| {
            LocalSendError::network(format!(
                "Invalid multicast address {DEFAULT_MULTICAST_ADDRESS}: {error}"
            ))
        })?;
    socket
        .join_multicast_v4(&multicast_addr, &interface)
        .map_err(|error| {
            LocalSendError::network(format!("Failed to join multicast on {interface}: {error}"))
        })?;
    socket.set_multicast_if_v4(&interface).map_err(|error| {
        LocalSendError::network(format!(
            "Failed to select multicast interface {interface}: {error}"
        ))
    })?;

    // Convert to tokio UdpSocket after configuring the multicast interface.
    let std_socket: std::net::UdpSocket = socket.into();
    std_socket
        .set_nonblocking(true)
        .map_err(|e| LocalSendError::network(format!("Failed to set non-blocking: {}", e)))?;

    UdpSocket::from_std(std_socket)
        .map_err(|e| LocalSendError::network(format!("Failed to convert to tokio socket: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::MulticastDiscovery;
    use std::net::Ipv4Addr;

    #[cfg(feature = "https")]
    use crate::{DeviceInfo, LocalSendServer, Protocol};

    #[cfg(feature = "https")]
    #[tokio::test]
    async fn announcement_client_pins_the_discovered_https_certificate() {
        let output = tempfile::tempdir().expect("output directory");
        let (mut server, _events) = LocalSendServer::builder()
            .alias("discovered HTTPS peer")
            .port(0)
            .save_dir(output.path())
            .protocol(Protocol::Https)
            .build()
            .await
            .expect("start HTTPS receiver");

        let mut peer = server.device().clone();
        peer.ip = Some("127.0.0.1".into());
        let local = DeviceInfo::new("discovery client".into(), 0, Protocol::Https);
        let client = MulticastDiscovery::client_for_announcement(local, &peer)
            .expect("build a client for the announced peer");

        client
            .register(&peer)
            .await
            .expect("the announced certificate fingerprint should be pinned");

        server.stop();
    }

    #[test]
    fn multicast_uses_each_interface_on_the_primary_lan_only() {
        assert_eq!(
            MulticastDiscovery::multicast_interfaces_from(
                [
                    (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(255, 255, 255, 0)),
                    (Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0)),
                    (
                        Ipv4Addr::new(192, 168, 6, 10),
                        Ipv4Addr::new(255, 255, 255, 0),
                    ),
                    (
                        Ipv4Addr::new(192, 168, 6, 101),
                        Ipv4Addr::new(255, 255, 255, 0),
                    ),
                    (
                        Ipv4Addr::new(192, 168, 139, 3),
                        Ipv4Addr::new(255, 255, 254, 0),
                    ),
                ],
                Some(Ipv4Addr::new(192, 168, 6, 101))
            ),
            vec![
                Ipv4Addr::new(192, 168, 6, 10),
                Ipv4Addr::new(192, 168, 6, 101),
            ]
        );
    }
}
