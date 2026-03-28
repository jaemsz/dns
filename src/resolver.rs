use crate::config::UpstreamResolverEntry;
use hickory_proto::ProtoErrorKind;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{ResolveErrorKind, TokioResolver};
use std::time::Duration;
use tracing::warn;

pub struct UpstreamResolver {
    inner: TokioResolver,
}

impl UpstreamResolver {
    /// Build an upstream resolver that connects to each entry via DNS-over-TLS.
    /// webpki root CAs are loaded automatically via the `webpki-roots` feature.
    pub fn new(resolvers: &[UpstreamResolverEntry], timeout_ms: u64) -> anyhow::Result<Self> {
        let mut config = ResolverConfig::new();
        for entry in resolvers {
            config.add_name_server(NameServerConfig {
                socket_addr: entry.addr,
                protocol: Protocol::Tls,
                tls_dns_name: Some(entry.tls_name.clone()),
                http_endpoint: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
        }

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(timeout_ms);
        opts.attempts = 2;
        opts.edns0 = true;
        opts.cache_size = 1024;

        let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();

        Ok(Self { inner: resolver })
    }

    /// Forward a DNS query Message to upstream over DoT and return the response.
    /// Preserves the original query ID so the client's transaction is matched correctly.
    pub async fn forward(&self, query: &Message) -> anyhow::Result<Message> {
        let question = query
            .queries()
            .first()
            .ok_or_else(|| anyhow::anyhow!("Query has no questions"))?;

        let name = question.name().clone();
        let record_type = question.query_type();

        match self.inner.lookup(name.clone(), record_type).await {
            Ok(response) => {
                let mut msg = Message::new();
                msg.set_id(query.id());
                msg.set_message_type(MessageType::Response);
                msg.set_op_code(OpCode::Query);
                msg.set_response_code(ResponseCode::NoError);
                msg.set_recursion_desired(query.recursion_desired());
                msg.set_recursion_available(true);
                msg.add_queries(query.queries().to_vec());
                for record in response.records() {
                    msg.add_answer(record.clone());
                }
                Ok(msg)
            }
            Err(e) => {
                // Propagate authoritative NXDOMAIN / NODATA from upstream
                if let ResolveErrorKind::Proto(proto) = e.kind() {
                    if let ProtoErrorKind::NoRecordsFound { response_code, .. } = proto.kind() {
                        let mut msg = Message::new();
                        msg.set_id(query.id());
                        msg.set_message_type(MessageType::Response);
                        msg.set_op_code(OpCode::Query);
                        msg.set_response_code(*response_code);
                        msg.set_recursion_desired(query.recursion_desired());
                        msg.set_recursion_available(true);
                        msg.add_queries(query.queries().to_vec());
                        return Ok(msg);
                    }
                }
                warn!(name = %name, record_type = ?record_type, error = %e, "Upstream DoT resolution failed");
                Err(anyhow::anyhow!("Upstream error: {e}"))
            }
        }
    }

    #[allow(dead_code)]
    pub async fn lookup_a(&self, name: &str) -> anyhow::Result<Vec<std::net::Ipv4Addr>> {
        let lookup = self
            .inner
            .lookup(hickory_proto::rr::Name::from_ascii(name)?, RecordType::A)
            .await?;
        let addrs = lookup
            .records()
            .iter()
            .filter_map(|r| {
                if let hickory_proto::rr::RData::A(a) = r.data() {
                    Some(a.0)
                } else {
                    None
                }
            })
            .collect();
        Ok(addrs)
    }
}
