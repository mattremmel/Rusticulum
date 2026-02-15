//! Tower `Service` adapters for [`AnyInterface`].
//!
//! Re-exports the request/response types from `reticulum-interfaces` and provides
//! Tower adapters for the node-level [`AnyInterface`] enum.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use reticulum_interfaces::InterfaceError;
use tower::Service;

pub use reticulum_interfaces::tower_service::{ReceivedPacket, TransmitRequest};

use crate::interface_enum::AnyInterface;

/// Wraps an [`AnyInterface`] as a `Service<TransmitRequest>`.
pub struct AnyTransmitService {
    interface: Arc<AnyInterface>,
}

impl AnyTransmitService {
    pub fn new(interface: Arc<AnyInterface>) -> Self {
        Self { interface }
    }
}

impl Clone for AnyTransmitService {
    fn clone(&self) -> Self {
        Self {
            interface: Arc::clone(&self.interface),
        }
    }
}

impl Service<TransmitRequest> for AnyTransmitService {
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

impl From<Arc<AnyInterface>> for AnyTransmitService {
    fn from(interface: Arc<AnyInterface>) -> Self {
        Self::new(interface)
    }
}

/// Wraps an [`AnyInterface`] as a `Service<()>` for receiving packets.
pub struct AnyReceiveService {
    interface: Arc<AnyInterface>,
}

impl AnyReceiveService {
    pub fn new(interface: Arc<AnyInterface>) -> Self {
        Self { interface }
    }
}

impl Clone for AnyReceiveService {
    fn clone(&self) -> Self {
        Self {
            interface: Arc::clone(&self.interface),
        }
    }
}

impl Service<()> for AnyReceiveService {
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

impl From<Arc<AnyInterface>> for AnyReceiveService {
    fn from(interface: Arc<AnyInterface>) -> Self {
        Self::new(interface)
    }
}
