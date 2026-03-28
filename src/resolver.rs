use crate::config::UpstreamResolverEntry;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::time::Duration;
use tracing::warn;

pub struct UpstreamResolver {
    inner: TokioAsyncResolver,
}

impl UpstreamResolver {
    /// Build an upstream resolver that connects to each entry via DNS-over-TLS.
    pub fn new(resolvers: &[UpstreamResolverEntry], timeout_ms: u64) -> anyhow::Result<Self> {
        let mut config = ResolverConfig::new();
        for entry in resolvers {
            config.add_name_server(NameServerConfig {
                socket_addr: entry.addr,
                protocol: Protocol::Tls,
                tls_dns_name: Some(entry.tls_name.clone()),
                trust_negative_responses: true,
                bind_addr: None,
                // None → hickory uses its built-in webpki root CAs
                tls_config: None,
            });
        }

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(timeout_ms);
        opts.attempts = 2;
        opts.rotate = true;
        opts.edns0 = true;
        opts.cache_size = 1024;

        let resolver = TokioAsyncResolver::tokio(config, opts);
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

        let lookup = self.inner.lookup(name.clone(), record_type).await;

        match lookup {
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
                use hickory_resolver::error::ResolveErrorKind;
                match e.kind() {
                    ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                        // Propagate authoritative NXDOMAIN / NODATA from upstream
                        let mut msg = Message::new();
                        msg.set_id(query.id());
                        msg.set_message_type(MessageType::Response);
                        msg.set_op_code(OpCode::Query);
                        msg.set_response_code(*response_code);
                        msg.set_recursion_desired(query.recursion_desired());
                        msg.set_recursion_available(true);
                        msg.add_queries(query.queries().to_vec());
                        Ok(msg)
                    }
                    _ => {
                        warn!(name = %name, record_type = ?record_type, error = %e, "Upstream DoT resolution failed");
                        Err(anyhow::anyhow!("Upstream error: {e}"))
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    pub async fn lookup_a(&self, name: &str) -> anyhow::Result<Vec<std::net::Ipv4Addr>> {
        let lookup = self
            .inner
            .lookup(
                hickory_proto::rr::Name::from_ascii(name)?,
                RecordType::A,
            )
            .await?;
        let addrs = lookup
            .records()
            .iter()
            .filter_map(|r| {
                if let Some(hickory_proto::rr::RData::A(a)) = r.data() {
                    Some(a.0)
                } else {
                    None
                }
            })
            .collect();
        Ok(addrs)
    }
}
