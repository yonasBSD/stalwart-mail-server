/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod inbound;
pub mod session;
/*pub mod lookup;
pub mod management;
pub mod outbound;
pub mod queue;
pub mod reporting;
*/

const CONFIG: &str = r#"
[session.connect]
hostname = "'mx.example.org'"
greeting = "'Test SMTP instance'"

[server.listener.smtp-debug]
bind = ['127.0.0.1:9925']
protocol = 'smtp'

[server.listener.lmtp-debug]
bind = ['127.0.0.1:9924']
protocol = 'lmtp'
tls.implicit = true

[server.listener.management-debug]
bind = ['127.0.0.1:9980']
protocol = 'http'
tls.implicit = true

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = 'default'

[certificate.default]
cert = '%{file:{CERT}}%'
private-key = '%{file:{PK}}%'

[storage]
data = "{STORE}"
fts = "{STORE}"
blob = "{STORE}"
lookup = "{STORE}"

[store."rocksdb"]
type = "rocksdb"
path = "{TMP}/queue.db"

#[store."foundationdb"]
#type = "foundationdb"

[store."postgresql"]
type = "postgresql"
host = "localhost"
port = 5432
database = "stalwart"
user = "postgres"
password = "mysecretpassword"

[store."mysql"]
type = "mysql"
host = "localhost"
port = 3307
database = "stalwart"
user = "root"
password = "password"

"#;
