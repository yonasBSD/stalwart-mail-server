/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::{SessionData, SessionManager, SessionStream};
use imap_proto::receiver::{self, Receiver};
use jmap::JMAP;
use tokio_rustls::server::TlsStream;

use crate::SERVER_GREETING;

use super::{ManageSieveSessionManager, Session, State};

impl SessionManager for ManageSieveSessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            // Create session
            let jmap = JMAP::from(self.imap.jmap_instance);
            let mut session = Session {
                receiver: Receiver::with_max_request_size(jmap.core.imap.max_request_size)
                    .with_start_state(receiver::State::Command { is_uid: false }),
                jmap,
                imap: self.imap.imap_inner,
                instance: session.instance,
                state: State::NotAuthenticated { auth_failures: 0 },
                span: session.span,
                stream: session.stream,
                in_flight: session.in_flight,
                remote_addr: session.remote_ip,
            };

            if session
                .write(&session.handle_capability(SERVER_GREETING).await.unwrap())
                .await
                .is_ok()
                && session.handle_conn().await
                && session.instance.acceptor.is_tls()
            {
                if let Ok(mut session) = session.into_tls().await {
                    let _ = session
                        .write(&session.handle_capability(SERVER_GREETING).await.unwrap())
                        .await;
                    session.handle_conn().await;
                }
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn handle_conn(&mut self) -> bool {
        let mut buf = vec![0; 8192];
        let mut shutdown_rx = self.instance.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = tokio::time::timeout(
                    if !matches!(self.state, State::NotAuthenticated {..}) {
                        self.jmap.core.imap.timeout_auth
                    } else {
                        self.jmap.core.imap.timeout_unauth
                    },
                    self.read(&mut buf)) => {
                        match result {
                            Ok(Ok(bytes_read)) => {
                                if bytes_read > 0 {
                                    match self.ingest(&buf[..bytes_read]).await {
                                        Ok(true) => (),
                                        Ok(false) => {
                                            return true;
                                        }
                                        Err(_) => {
                                            break;
                                        }
                                    }
                                } else {
                                    tracing::debug!(
                                        parent: &self.span,
                                        event = "disconnect",
                                        reason = "peer",
                                        "Connection closed by peer."
                                    );
                                    break;
                                }
                            }
                            Ok(Err(_)) => {
                                break;
                            }
                            Err(_) => {
                                tracing::debug!(
                                    parent: &self.span,
                                    event = "disconnect",
                                    reason = "timeout",
                                    "Connection timed out."
                                );
                                self
                                    .write(b"BYE \"Connection timed out.\"\r\n")
                                    .await
                                    .ok();
                                break;
                            }
                        }
                },
                _ = shutdown_rx.changed() => {
                    tracing::debug!(
                        parent: &self.span,
                        event = "disconnect",
                        reason = "shutdown",
                        "Server shutting down."
                    );
                    self.write(b"BYE \"Server shutting down.\"\r\n").await.ok();
                    break;
                }
            };
        }

        false
    }

    pub async fn into_tls(self) -> Result<Session<TlsStream<T>>, ()> {
        let span = self.span;
        Ok(Session {
            stream: self.instance.tls_accept(self.stream, &span).await?,
            state: self.state,
            instance: self.instance,
            in_flight: self.in_flight,
            span,
            jmap: self.jmap,
            imap: self.imap,
            receiver: self.receiver,
            remote_addr: self.remote_addr,
        })
    }
}
