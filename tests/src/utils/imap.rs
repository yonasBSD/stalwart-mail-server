/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose};
use imap_proto::ResponseType;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};

pub struct ImapConnection {
    tag: &'static [u8],
    reader: Lines<BufReader<ReadHalf<TcpStream>>>,
    writer: WriteHalf<TcpStream>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Tagged,
    Untagged,
    Continuation,
    Status,
}

impl ImapConnection {
    pub async fn connect(tag: &'static [u8]) -> Self {
        Self::connect_to(tag, "127.0.0.1:9991").await
    }

    pub async fn connect_to(tag: &'static [u8], addr: impl AsRef<str>) -> Self {
        let (reader, writer) = tokio::io::split(TcpStream::connect(addr.as_ref()).await.unwrap());
        ImapConnection {
            tag,
            reader: BufReader::new(reader).lines(),
            writer,
        }
    }

    pub async fn assert_read(&mut self, t: Type, rt: ResponseType) -> Vec<String> {
        let lines = self.read(t).await;
        let mut buf = Vec::with_capacity(10);
        buf.extend_from_slice(match t {
            Type::Tagged => self.tag,
            Type::Untagged | Type::Status => b"* ",
            Type::Continuation => b"+ ",
        });
        if !matches!(t, Type::Continuation | Type::Status) {
            rt.serialize(&mut buf);
        }
        if lines
            .last()
            .unwrap()
            .starts_with(&String::from_utf8(buf).unwrap())
        {
            lines
        } else {
            panic!("Expected {:?}/{:?} from server but got: {:?}", t, rt, lines);
        }
    }

    pub async fn assert_disconnect(&mut self) {
        match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
            Ok(Ok(None)) => {}
            Ok(Ok(Some(line))) => {
                panic!("Expected connection to be closed, but got {:?}", line);
            }
            Ok(Err(err)) => {
                panic!("Connection broken: {:?}", err);
            }
            Err(_) => panic!("Timeout while waiting for server response."),
        }
    }

    pub async fn read(&mut self, t: Type) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let is_done = line.starts_with(match t {
                        Type::Tagged => std::str::from_utf8(self.tag).unwrap(),
                        Type::Untagged | Type::Status => "* ",
                        Type::Continuation => "+ ",
                    });
                    //let c = println!("<- {:?}", line);
                    lines.push(line);
                    if is_done {
                        return lines;
                    }
                }
                Ok(Ok(None)) => {
                    panic!("Invalid response: {:?}.", lines);
                }
                Ok(Err(err)) => {
                    panic!("Connection broken: {} ({:?})", err, lines);
                }
                Err(_) => panic!("Timeout while waiting for server response: {:?}", lines),
            }
        }
    }

    pub async fn authenticate(&mut self, user: &str, pass: &str) {
        let creds = general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
        self.send(&format!(
            "AUTHENTICATE PLAIN {{{}+}}\r\n{creds}",
            creds.len()
        ))
        .await;
        self.assert_read(Type::Tagged, ResponseType::Ok).await;
    }

    pub async fn send(&mut self, text: &str) {
        //let c = println!("-> {}{:?}", std::str::from_utf8(self.tag).unwrap(), text);
        self.writer.write_all(self.tag).await.unwrap();
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_untagged(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }

    pub async fn append(&mut self, mailbox: &str, message: &str) {
        self.send_ok(&format!(
            "APPEND {:?} {{{}+}}\r\n{}",
            mailbox,
            message.len(),
            message
        ))
        .await;
    }

    pub async fn send_ok(&mut self, cmd: &str) {
        self.send(cmd).await;
        self.assert_read(Type::Tagged, ResponseType::Ok).await;
    }
}
