//! Unified enum wrapping all concrete interface types for static dispatch.

use reticulum_interfaces::tcp::{TcpClientInterface, TcpServerInterface};
use reticulum_interfaces::udp::UdpInterface;
use reticulum_interfaces::{Interface, InterfaceError, InterfaceId, InterfaceMode};

#[cfg(unix)]
use reticulum_interfaces::auto::AutoInterface;
#[cfg(unix)]
use reticulum_interfaces::local::{LocalClientInterface, LocalServerInterface};

/// Wraps all concrete interface types, dispatching trait methods via match.
pub enum AnyInterface {
    TcpClient(TcpClientInterface),
    TcpServer(TcpServerInterface),
    Udp(UdpInterface),
    #[cfg(unix)]
    LocalClient(LocalClientInterface),
    #[cfg(unix)]
    LocalServer(LocalServerInterface),
    #[cfg(unix)]
    Auto(AutoInterface),
}

/// Delegate a sync method that returns a concrete (non-opaque) type.
macro_rules! delegate_sync {
    ($self:ident, $method:ident $(, $arg:expr)*) => {
        match $self {
            Self::TcpClient(i) => i.$method($($arg),*),
            Self::TcpServer(i) => i.$method($($arg),*),
            Self::Udp(i) => i.$method($($arg),*),
            #[cfg(unix)]
            Self::LocalClient(i) => i.$method($($arg),*),
            #[cfg(unix)]
            Self::LocalServer(i) => i.$method($($arg),*),
            #[cfg(unix)]
            Self::Auto(i) => i.$method($($arg),*),
        }
    };
}

impl AnyInterface {
    pub fn name(&self) -> &str {
        delegate_sync!(self, name)
    }

    pub fn id(&self) -> InterfaceId {
        delegate_sync!(self, id)
    }

    pub fn mode(&self) -> InterfaceMode {
        delegate_sync!(self, mode)
    }

    pub fn bitrate(&self) -> u64 {
        delegate_sync!(self, bitrate)
    }

    pub fn mtu(&self) -> usize {
        delegate_sync!(self, mtu)
    }

    pub fn can_receive(&self) -> bool {
        delegate_sync!(self, can_receive)
    }

    pub fn can_transmit(&self) -> bool {
        delegate_sync!(self, can_transmit)
    }

    pub fn is_connected(&self) -> bool {
        delegate_sync!(self, is_connected)
    }

    pub async fn start(&self) -> Result<(), InterfaceError> {
        match self {
            Self::TcpClient(i) => i.start().await,
            Self::TcpServer(i) => i.start().await,
            Self::Udp(i) => i.start().await,
            #[cfg(unix)]
            Self::LocalClient(i) => i.start().await,
            #[cfg(unix)]
            Self::LocalServer(i) => i.start().await,
            #[cfg(unix)]
            Self::Auto(i) => i.start().await,
        }
    }

    pub async fn stop(&self) -> Result<(), InterfaceError> {
        match self {
            Self::TcpClient(i) => i.stop().await,
            Self::TcpServer(i) => i.stop().await,
            Self::Udp(i) => i.stop().await,
            #[cfg(unix)]
            Self::LocalClient(i) => i.stop().await,
            #[cfg(unix)]
            Self::LocalServer(i) => i.stop().await,
            #[cfg(unix)]
            Self::Auto(i) => i.stop().await,
        }
    }

    pub async fn transmit(&self, data: &[u8]) -> Result<(), InterfaceError> {
        match self {
            Self::TcpClient(i) => i.transmit(data).await,
            Self::TcpServer(i) => i.transmit(data).await,
            Self::Udp(i) => i.transmit(data).await,
            #[cfg(unix)]
            Self::LocalClient(i) => i.transmit(data).await,
            #[cfg(unix)]
            Self::LocalServer(i) => i.transmit(data).await,
            #[cfg(unix)]
            Self::Auto(i) => i.transmit(data).await,
        }
    }

    pub async fn receive(&self) -> Result<Vec<u8>, InterfaceError> {
        match self {
            Self::TcpClient(i) => i.receive().await,
            Self::TcpServer(i) => i.receive().await,
            Self::Udp(i) => i.receive().await,
            #[cfg(unix)]
            Self::LocalClient(i) => i.receive().await,
            #[cfg(unix)]
            Self::LocalServer(i) => i.receive().await,
            #[cfg(unix)]
            Self::Auto(i) => i.receive().await,
        }
    }

    /// Transmit data to all connected local clients (only meaningful for LocalServer).
    /// No-op for all other interface types.
    #[cfg(unix)]
    pub async fn transmit_to_local_clients(&self, data: &[u8]) {
        if let Self::LocalServer(server) = self {
            server.transmit_to_clients(data).await;
        }
    }

    /// Whether this interface is a local shared-instance server.
    pub fn is_local_shared_instance(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self, Self::LocalServer(_))
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

impl std::fmt::Debug for AnyInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnyInterface({})", self.name())
    }
}
