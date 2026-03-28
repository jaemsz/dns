use crate::blacklist::SharedBlocklist;
use crate::config::{BlockResponse, Config};
use crate::resolver::UpstreamResolver;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

const MAX_UDP_PAYLOAD: usize = 4096;

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

        // Forward to upstream
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
                    // Return sinkhole A record for A queries
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
                    // Return sinkhole AAAA record for AAAA queries
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
