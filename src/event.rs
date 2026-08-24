//! Voice connection events and listener dispatch.
//!
//! A [`VoiceConnection`](crate::connection::VoiceConnection) dispatches [`VoiceEvent`]s to
//! registered listeners as its lifecycle progresses: the gateway becoming ready, the DAVE
//! session activating, other users joining/leaving, and the gateway closing or erroring.
//! Listeners are invoked synchronously and must not block.

use std::sync::{Arc, Mutex};

/// An event emitted by a [`VoiceConnection`](crate::connection::VoiceConnection).
#[derive(Debug, Clone)]
pub enum VoiceEvent {
    /// The voice gateway is ready: SSRC assigned and the voice server UDP endpoint known.
    GatewayReady {
        /// Our synchronization source.
        ssrc: u32,
        /// Voice server UDP IP.
        ip: String,
        /// Voice server UDP port.
        port: u16,
    },
    /// Our external address was discovered via UDP IP discovery.
    ExternalIpDiscovered {
        /// Our public IP.
        ip: String,
        /// Our public UDP port.
        port: u16,
    },
    /// `SESSION_DESCRIPTION` received: transport mode and DAVE protocol version negotiated.
    SessionDescription {
        /// Negotiated transport encryption mode.
        mode: String,
        /// DAVE protocol version (0 = disabled for this channel).
        dave_protocol_version: u16,
    },
    /// The DAVE MLS group became active; end-to-end encryption is now in effect. Carries the
    /// human-verifiable voice privacy code, if available.
    DaveSessionReady {
        /// The 30-digit voice privacy code.
        privacy_code: Option<String>,
    },
    /// Another user connected to the voice channel (op 12 `CLIENT_CONNECT`).
    UserConnected {
        /// The user's id.
        user_id: String,
        /// The user's audio SSRC.
        audio_ssrc: u32,
    },
    /// Another user disconnected (op 13 `CLIENT_DISCONNECT`).
    UserDisconnected {
        /// The user's id.
        user_id: String,
    },
    /// The gateway WebSocket closed and will not be resumed. The higher layer should reconnect
    /// with fresh voice-server info if appropriate.
    GatewayClosed {
        /// WebSocket close code.
        code: u16,
        /// Close reason text.
        reason: String,
        /// Whether the close was initiated by the remote (Discord).
        by_remote: bool,
    },
    /// A gateway-level error occurred.
    GatewayError {
        /// A description of the error.
        message: String,
    },
}

/// A listener for [`VoiceEvent`]s.
///
/// Invoked synchronously on a gateway/send task; handlers must be quick and must not block.
pub trait VoiceEventListener: Send + Sync {
    /// Handle an event.
    fn on_event(&self, event: &VoiceEvent);
}

/// Adapter that dispatches [`VoiceEvent`]s to individual methods. Override only the callbacks you
/// care about.
pub trait VoiceEventAdapter: Send + Sync {
    /// The gateway became ready (SSRC + voice server endpoint).
    fn on_gateway_ready(&self, _ssrc: u32, _ip: &str, _port: u16) {}
    /// Our external address was discovered.
    fn on_external_ip_discovered(&self, _ip: &str, _port: u16) {}
    /// `SESSION_DESCRIPTION` was received.
    fn on_session_description(&self, _mode: &str, _dave_protocol_version: u16) {}
    /// The DAVE session became active.
    fn on_dave_session_ready(&self, _privacy_code: Option<&str>) {}
    /// Another user connected.
    fn on_user_connected(&self, _user_id: &str, _audio_ssrc: u32) {}
    /// Another user disconnected.
    fn on_user_disconnected(&self, _user_id: &str) {}
    /// The gateway closed and will not be resumed.
    fn on_gateway_closed(&self, _code: u16, _reason: &str, _by_remote: bool) {}
    /// A gateway error occurred.
    fn on_gateway_error(&self, _message: &str) {}
}

impl<T: VoiceEventAdapter> VoiceEventListener for T {
    fn on_event(&self, event: &VoiceEvent) {
        match event {
            VoiceEvent::GatewayReady { ssrc, ip, port } => self.on_gateway_ready(*ssrc, ip, *port),
            VoiceEvent::ExternalIpDiscovered { ip, port } => {
                self.on_external_ip_discovered(ip, *port)
            }
            VoiceEvent::SessionDescription {
                mode,
                dave_protocol_version,
            } => self.on_session_description(mode, *dave_protocol_version),
            VoiceEvent::DaveSessionReady { privacy_code } => {
                self.on_dave_session_ready(privacy_code.as_deref())
            }
            VoiceEvent::UserConnected {
                user_id,
                audio_ssrc,
            } => self.on_user_connected(user_id, *audio_ssrc),
            VoiceEvent::UserDisconnected { user_id } => self.on_user_disconnected(user_id),
            VoiceEvent::GatewayClosed {
                code,
                reason,
                by_remote,
            } => self.on_gateway_closed(*code, reason, *by_remote),
            VoiceEvent::GatewayError { message } => self.on_gateway_error(message),
        }
    }
}

/// Synchronous fan-out of [`VoiceEvent`]s to registered listeners. Cheaply cloneable (shares the
/// listener set).
#[derive(Clone, Default)]
pub struct EventDispatcher {
    listeners: Arc<Mutex<Vec<Arc<dyn VoiceEventListener>>>>,
}

impl EventDispatcher {
    /// Create an empty dispatcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a listener.
    pub fn register(&self, listener: Arc<dyn VoiceEventListener>) {
        self.listeners.lock().unwrap().push(listener);
    }

    /// Remove a previously registered listener (by `Arc` identity).
    pub fn unregister(&self, listener: &Arc<dyn VoiceEventListener>) {
        self.listeners
            .lock()
            .unwrap()
            .retain(|l| !Arc::ptr_eq(l, listener));
    }

    /// Dispatch an event to all listeners.
    pub fn dispatch(&self, event: VoiceEvent) {
        let listeners: Vec<Arc<dyn VoiceEventListener>> = self.listeners.lock().unwrap().clone();
        for listener in listeners {
            listener.on_event(&event);
        }
    }
}
