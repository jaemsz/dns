use crate::blacklist::SharedBlocklist;
use crate::config::{BlockResponse, Config};
use crate::resolver::UpstreamResolver;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

const MAX_UDP_PAYLOAD: usize = 4096;
/// RFC 1035 §4.2.2: TCP messages are prefixed with a 2-byte length.
const MAX_TCP_MSG: usize = 65535;

pub struct DnsServer {
    config: Arc<Config>,
    resolver: Arc<UpstreamResolver>,
    blocklist: SharedBlocklist,
}

impl DnsServer {
    pub fn new(
        config: Arc<Config>,
        resolver: Arc<UpstreamResolver>,
        blocklist: SharedBlocklist,
    ) -> Self {
        Self {
            config,
            resolver,
            blocklist,
        }
    }

    // ── UDP (plaintext) ──────────────────────────────────────────────────────

    pub async fn run_udp(self: Arc<Self>) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(self.config.server.listen_udp).await?;
        info!(addr = %self.config.server.listen_udp, "UDP listener started");

        let socket = Arc::new(socket);
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    let query_bytes = buf[..len].to_vec();
                    let server = Arc::clone(&self);
                    let sock = Arc::clone(&socket);
                    tokio::spawn(async move {
                        server.handle_udp_query(sock, query_bytes, peer).await;
                    });
                }
                Err(e) => error!("UDP recv error: {e}"),
            }
        }
    }

    async fn handle_udp_query(
        &self,
        socket: Arc<UdpSocket>,
        query_bytes: Vec<u8>,
        peer: SocketAddr,
    ) {
        let response_bytes = match self.process_query(&query_bytes).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(peer = %peer, "Query processing error: {e}");
                return;
            }
        };

        if let Err(e) = socket.send_to(&response_bytes, peer).await {
            error!("UDP send error to {peer}: {e}");
        }
    }

    // ── DoT (DNS-over-TLS, RFC 7858) ─────────────────────────────────────────

    /// Accept incoming DoT connections. Each connection is handled in its own task.
    /// DNS-over-TLS uses standard TCP DNS framing: 2-byte BE length + message bytes.
    pub async fn run_dot(self: Arc<Self>, acceptor: TlsAcceptor, listen: SocketAddr) -> anyhow::Result<()> {
        let listener = TcpListener::bind(listen).await?;
        info!(addr = %listen, "DoT listener started");

        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer)) => {
                    let acceptor = acceptor.clone();
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        match acceptor.accept(tcp_stream).await {
                            Ok(tls_stream) => {
                                debug!(peer = %peer, "DoT TLS handshake complete");
                                server.handle_dot_connection(tls_stream, peer).await;
                            }
                            Err(e) => warn!(peer = %peer, "DoT TLS handshake failed: {e}"),
                        }
                    });
                }
                Err(e) => error!("DoT accept error: {e}"),
            }
        }
    }

    /// Handle a single DoT connection: read queries and write responses until the
    /// client closes. Multiple queries may be pipelined over one connection (RFC 7858 §3.3).
    async fn handle_dot_connection<S>(&self, mut stream: S, peer: SocketAddr)
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        loop {
            // Read 2-byte big-endian message length
            let mut len_buf = [0u8; 2];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Client closed the connection cleanly
                    break;
                }
                Err(e) => {
                    warn!(peer = %peer, "DoT read length error: {e}");
                    break;
                }
            }

            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 || msg_len > MAX_TCP_MSG {
                warn!(peer = %peer, msg_len, "DoT invalid message length");
                break;
            }

            // Read the DNS message
            let mut msg_buf = vec![0u8; msg_len];
            if let Err(e) = stream.read_exact(&mut msg_buf).await {
                warn!(peer = %peer, "DoT read message error: {e}");
                break;
            }

            // Process and respond
            let response = match self.process_query(&msg_buf).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(peer = %peer, "DoT query processing error: {e}");
                    break;
                }
            };

            // Write 2-byte length prefix + response
            let resp_len = response.len() as u16;
            if let Err(e) = stream.write_all(&resp_len.to_be_bytes()).await {
                warn!(peer = %peer, "DoT write length error: {e}");
                break;
            }
            if let Err(e) = stream.write_all(&response).await {
                warn!(peer = %peer, "DoT write response error: {e}");
                break;
            }
        }
    }

    // ── Shared query processing ───────────────────────────────────────────────

    async fn process_query(&self, query_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let query = Message::from_bytes(query_bytes)
            .map_err(|e| anyhow::anyhow!("DNS parse error: {e}"))?;

        if query.message_type() != MessageType::Query {
            anyhow::bail!("Not a query message");
        }

        if query.op_code() != OpCode::Query {
            return build_not_impl(&query);
        }

        let domain = match query.queries().first() {
            Some(q) => q.name().to_string(),
            None => anyhow::bail!("Empty question section"),
        };

        debug!(domain = %domain, "Processing query");

        // Lock-free blocklist check via ArcSwap::load()
        let bl = self.blocklist.load();
        if bl.is_blocked(&domain) {
            info!(domain = %domain, "Blocked query");
            return self.build_blocked_response(&query);
        }

        // Forward to upstream over DoT
        match self.resolver.forward(&query).await {
            Ok(response) => response
                .to_bytes()
                .map_err(|e| anyhow::anyhow!("Encode upstream response: {e}")),
            Err(_) => build_servfail(&query),
        }
    }

    fn build_blocked_response(&self, query: &Message) -> anyhow::Result<Vec<u8>> {
        let mut resp = base_response(query);
        match self.config.blocklist.block_response {
            BlockResponse::Nxdomain => {
                resp.set_response_code(ResponseCode::NXDomain);
            }
            BlockResponse::Sinkhole => {
                resp.set_response_code(ResponseCode::NoError);
                if let Some(question) = query.queries().first() {
                    if question.query_type() == RecordType::A {
                        let mut record = Record::new();
                        record.set_name(question.name().clone());
                        record.set_ttl(60);
                        record.set_record_type(RecordType::A);
                        record.set_data(Some(RData::A(hickory_proto::rr::rdata::A(
                            self.config.blocklist.sinkhole_ipv4,
                        ))));
                        resp.add_answer(record);
                    }
                    if question.query_type() == RecordType::AAAA {
                        let mut record = Record::new();
                        record.set_name(question.name().clone());
                        record.set_ttl(60);
                        record.set_record_type(RecordType::AAAA);
                        record.set_data(Some(RData::AAAA(hickory_proto::rr::rdata::AAAA(
                            self.config.blocklist.sinkhole_ipv6,
                        ))));
                        resp.add_answer(record);
                    }
                }
            }
        }
        resp.to_bytes()
            .map_err(|e| anyhow::anyhow!("Encode blocked response: {e}"))
    }
}

fn base_response(query: &Message) -> Message {
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_desired(query.recursion_desired());
    resp.set_recursion_available(true);
    resp.add_queries(query.queries().to_vec());
    resp
}

fn build_servfail(query: &Message) -> anyhow::Result<Vec<u8>> {
    let mut resp = base_response(query);
    resp.set_response_code(ResponseCode::ServFail);
    resp.to_bytes()
        .map_err(|e| anyhow::anyhow!("Encode SERVFAIL: {e}"))
}

fn build_not_impl(query: &Message) -> anyhow::Result<Vec<u8>> {
    let mut resp = base_response(query);
    resp.set_response_code(ResponseCode::NotImp);
    resp.to_bytes()
        .map_err(|e| anyhow::anyhow!("Encode NOTIMP: {e}"))
}
