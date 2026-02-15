//! Tower `Service` adapters for Reticulum interfaces.
//!
//! These adapters wrap any type implementing [`Interface`] as a [`tower::Service`],
//! enabling composition with Tower middleware (rate limiting, timeout, retry, etc.).
//!
//! # Example
//!
//! ```rust,ignore
//! use tower::ServiceBuilder;
//! use tower::limit::RateLimitLayer;
//! use tower::timeout::TimeoutLayer;
//! use reticulum_interfaces::tower_service::{TransmitService, TransmitRequest};
//!
//! let iface = TcpClientInterface::new(/* ... */);
//! let svc = ServiceBuilder::new()
//!     .layer(RateLimitLayer::new(100, Duration::from_secs(1)))
//!     .layer(TimeoutLayer::new(Duration::from_secs(5)))
//!     .service(TransmitService::new(Arc::new(iface)));
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tower::Service;

use crate::error::InterfaceError;
use crate::traits::Interface;

/// A packet to transmit through an interface.
#[derive(Debug, Clone)]
pub struct TransmitRequest {
    pub data: Vec<u8>,
}

/// A packet received from an interface.
#[derive(Debug, Clone)]
pub struct ReceivedPacket {
    pub data: Vec<u8>,
}

/// Wraps a concrete [`Interface`] as a `Service<TransmitRequest>`.
///
/// `poll_ready` checks `is_connected()`; `call` delegates to `transmit()`.
pub struct TransmitService<I> {
    interface: Arc<I>,
}

impl<I> TransmitService<I> {
    pub fn new(interface: Arc<I>) -> Self {
        Self { interface }
    }
}

impl<I> Clone for TransmitService<I> {
    fn clone(&self) -> Self {
        Self {
            interface: Arc::clone(&self.interface),
        }
    }
}

impl<I: Interface + 'static> Service<TransmitRequest> for TransmitService<I> {
    type Response = ();
    type Error = InterfaceError;
    type Future = Pin<Box<dyn Future<Output = Result<(), InterfaceError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.interface.is_connected() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(InterfaceError::NotConnected))
        }
    }

    fn call(&mut self, req: TransmitRequest) -> Self::Future {
        let iface = Arc::clone(&self.interface);
        Box::pin(async move { iface.transmit(&req.data).await })
    }
}

impl<I> From<Arc<I>> for TransmitService<I> {
    fn from(interface: Arc<I>) -> Self {
        Self::new(interface)
    }
}

/// Wraps a concrete [`Interface`] as a `Service<()>` for receiving packets.
///
/// Each `call(())` returns the next packet from the interface.
pub struct ReceiveService<I> {
    interface: Arc<I>,
}

impl<I> ReceiveService<I> {
    pub fn new(interface: Arc<I>) -> Self {
        Self { interface }
    }
}

impl<I> Clone for ReceiveService<I> {
    fn clone(&self) -> Self {
        Self {
            interface: Arc::clone(&self.interface),
        }
    }
}

impl<I: Interface + 'static> Service<()> for ReceiveService<I> {
    type Response = ReceivedPacket;
    type Error = InterfaceError;
    type Future = Pin<Box<dyn Future<Output = Result<ReceivedPacket, InterfaceError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        let iface = Arc::clone(&self.interface);
        Box::pin(async move {
            let data = iface.receive().await?;
            Ok(ReceivedPacket { data })
        })
    }
}

impl<I> From<Arc<I>> for ReceiveService<I> {
    fn from(interface: Arc<I>) -> Self {
        Self::new(interface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum_transport::path::{InterfaceId, InterfaceMode};
    use tokio::sync::Mutex;

    /// Minimal mock for testing Tower adapters.
    struct MockInterface {
        connected: bool,
        transmitted: Mutex<Vec<Vec<u8>>>,
        incoming: Mutex<Vec<Vec<u8>>>,
    }

    impl MockInterface {
        fn new(connected: bool) -> Self {
            Self {
                connected,
                transmitted: Mutex::new(Vec::new()),
                incoming: Mutex::new(Vec::new()),
            }
        }

        async fn push_incoming(&self, data: Vec<u8>) {
            self.incoming.lock().await.push(data);
        }
    }

    impl Interface for MockInterface {
        fn name(&self) -> &str {
            "MockInterface"
        }
        fn id(&self) -> InterfaceId {
            InterfaceId(1)
        }
        fn mode(&self) -> InterfaceMode {
            InterfaceMode::Full
        }
        fn bitrate(&self) -> u64 {
            1_000_000
        }
        fn can_receive(&self) -> bool {
            true
        }
        fn can_transmit(&self) -> bool {
            true
        }
        fn is_connected(&self) -> bool {
            self.connected
        }
        async fn start(&self) -> Result<(), InterfaceError> {
            Ok(())
        }
        async fn stop(&self) -> Result<(), InterfaceError> {
            Ok(())
        }
        async fn transmit(&self, data: &[u8]) -> Result<(), InterfaceError> {
            if !self.connected {
                return Err(InterfaceError::NotConnected);
            }
            self.transmitted.lock().await.push(data.to_vec());
            Ok(())
        }
        async fn receive(&self) -> Result<Vec<u8>, InterfaceError> {
            self.incoming
                .lock()
                .await
                .pop()
                .ok_or(InterfaceError::ReceiveFailed("empty".into()))
        }
    }

    #[tokio::test]
    async fn transmit_service_delegates_to_interface() {
        let mock = Arc::new(MockInterface::new(true));
        let mut svc = TransmitService::new(Arc::clone(&mock));

        let ready = std::future::poll_fn(|cx| svc.poll_ready(cx)).await;
        assert!(ready.is_ok());

        let result = svc
            .call(TransmitRequest {
                data: vec![1, 2, 3],
            })
            .await;
        assert!(result.is_ok());

        let sent = mock.transmitted.lock().await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0], vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn transmit_service_not_ready_when_disconnected() {
        let mock = Arc::new(MockInterface::new(false));
        let mut svc = TransmitService::new(mock);

        let ready = std::future::poll_fn(|cx| svc.poll_ready(cx)).await;
        assert!(matches!(ready, Err(InterfaceError::NotConnected)));
    }

    #[tokio::test]
    async fn receive_service_delegates_to_interface() {
        let mock = Arc::new(MockInterface::new(true));
        mock.push_incoming(vec![0xAA, 0xBB]).await;

        let mut svc = ReceiveService::new(mock);

        let ready = std::future::poll_fn(|cx| svc.poll_ready(cx)).await;
        assert!(ready.is_ok());

        let packet = svc.call(()).await.unwrap();
        assert_eq!(packet.data, vec![0xAA, 0xBB]);
    }

    #[tokio::test]
    async fn receive_service_returns_error_when_empty() {
        let mock = Arc::new(MockInterface::new(true));
        let mut svc = ReceiveService::new(mock);

        let result = svc.call(()).await;
        assert!(result.is_err());
    }

    #[test]
    fn transmit_service_is_clone() {
        let mock = Arc::new(MockInterface::new(true));
        let svc = TransmitService::new(mock);
        let _clone = svc.clone();
    }

    #[test]
    fn receive_service_is_clone() {
        let mock = Arc::new(MockInterface::new(true));
        let svc = ReceiveService::new(mock);
        let _clone = svc.clone();
    }

    #[test]
    fn transmit_service_from_arc() {
        let mock = Arc::new(MockInterface::new(true));
        let _svc: TransmitService<MockInterface> = mock.into();
    }

    #[test]
    fn receive_service_from_arc() {
        let mock = Arc::new(MockInterface::new(true));
        let _svc: ReceiveService<MockInterface> = mock.into();
    }
}
