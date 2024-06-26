/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::listener::SessionStream;
use imap_proto::{
    protocol::{capability::Capability, enable, ImapResponse, ProtocolVersion},
    receiver::Request,
    Command, StatusResponse,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_enable(&mut self, request: Request<Command>) -> crate::OpResult {
        match request.parse_enable() {
            Ok(arguments) => {
                let mut response = enable::Response {
                    enabled: Vec::with_capacity(arguments.capabilities.len()),
                };
                for capability in arguments.capabilities {
                    match capability {
                        Capability::IMAP4rev2 => {
                            self.version = ProtocolVersion::Rev2;
                        }
                        Capability::IMAP4rev1 => {
                            self.version = ProtocolVersion::Rev1;
                        }
                        Capability::CondStore => {
                            self.is_condstore = true;
                        }
                        Capability::QResync => {
                            self.is_qresync = true;
                            self.is_condstore = true;
                        }
                        Capability::Utf8Accept => {}
                        _ => {
                            continue;
                        }
                    }
                    response.enabled.push(capability);
                }

                self.write_bytes(
                    StatusResponse::ok("ENABLE successful.")
                        .with_tag(arguments.tag)
                        .serialize(response.serialize()),
                )
                .await
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }
}
