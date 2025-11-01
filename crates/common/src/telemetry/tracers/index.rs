fn build_index() {
    let mut queue_ids = AHashSet::new();
    let mut values = AHashSet::new();

    for event in events.iter().chain([span, &event]) {
        for (key, value) in &event.keys {
            match (key, value) {
                (Key::QueueId, Value::UInt(queue_id)) => {
                    queue_ids.insert(*queue_id);
                }
                (Key::From | Key::To | Key::Domain | Key::Hostname, Value::String(address)) => {
                    values.insert(address.clone());
                }
                (Key::To, Value::Array(value)) => {
                    for value in value {
                        if let Value::String(address) = value {
                            values.insert(address.clone());
                        }
                    }
                }
                (Key::RemoteIp, Value::Ipv4(ip)) => {
                    values.insert(ip.to_string().into());
                }
                (Key::RemoteIp, Value::Ipv6(ip)) => {
                    values.insert(ip.to_string().into());
                }

                _ => {}
            }
        }
    }
    // Build index
    batch.set(
        ValueClass::Telemetry(TelemetryClass::Index {
            span_id,
            value: (span.inner.typ.code() as u16).to_be_bytes().to_vec(),
        }),
        vec![],
    );
    for queue_id in queue_ids {
        batch.set(
            ValueClass::Telemetry(TelemetryClass::Index {
                span_id,
                value: queue_id.to_be_bytes().to_vec(),
            }),
            vec![],
        );
    }
    for value in values {
        batch.set(
            ValueClass::Telemetry(TelemetryClass::Index {
                span_id,
                value: value.as_bytes().to_vec(),
            }),
            vec![],
        );
    }
}

/*


enum SpanCollector {
    Vec(Vec<u64>),
    HashSet(AHashSet<u64>),
    Empty,
}

impl SpanCollector {
    fn new(num_params: usize) -> Self {
        if num_params == 1 {
            Self::Vec(Vec::new())
        } else {
            Self::HashSet(AHashSet::new())
        }
    }

    fn insert(&mut self, span_id: u64) {
        match self {
            Self::Vec(vec) => vec.push(span_id),
            Self::HashSet(set) => {
                set.insert(span_id);
            }
            _ => unreachable!(),
        }
    }

    fn into_vec(self) -> Vec<u64> {
        match self {
            Self::Vec(mut vec) => {
                vec.sort_unstable_by(|a, b| b.cmp(a));
                vec
            }
            Self::HashSet(set) => {
                let mut vec: Vec<u64> = set.into_iter().collect();
                vec.sort_unstable_by(|a, b| b.cmp(a));
                vec
            }
            Self::Empty => Vec::new(),
        }
    }

    fn intersect(&mut self, other_span: Self) -> bool {
        match (self, other_span) {
            (Self::HashSet(set), Self::HashSet(other_set)) => {
                set.retain(|span_id| other_set.contains(span_id));
                set.is_empty()
            }
            _ => unreachable!(),
        }
    }
}

        let mut spans = SpanCollector::Empty;
        let num_params = params.len();
        let todo = "use FTS";

        for (param_num, param) in params.iter().enumerate() {
            let (value, exact_len) = match param {
                TracingQuery::EventType(event) => (
                    (event.code() as u16).to_be_bytes().to_vec(),
                    std::mem::size_of::<u16>() + U64_LEN,
                ),
                TracingQuery::QueueId(id) => (
                    id.to_be_bytes().to_vec(),
                    std::mem::size_of::<u64>() + U64_LEN,
                ),
                TracingQuery::Keywords(value) => {
                    if let Some(value) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                        (value.as_bytes().to_vec(), value.len() + U64_LEN)
                    } else {
                        (value.as_bytes().to_vec(), 0)
                    }
                }
            };

            let mut param_spans = SpanCollector::new(num_params);
            self.iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::Telemetry(TelemetryClass::Index {
                        span_id: 0,
                        value: value.clone(),
                    })),
                    ValueKey::from(ValueClass::Telemetry(TelemetryClass::Index {
                        span_id: u64::MAX,
                        value,
                    })),
                )
                .no_values(),
                |key, _| {
                    if exact_len == 0 || key.len() == exact_len {
                        let span_id = key
                            .deserialize_be_u64(key.len() - U64_LEN)
                            .caused_by(trc::location!())?;

                        if (from_span_id == 0 || span_id >= from_span_id)
                            && (to_span_id == 0 || span_id <= to_span_id)
                        {
                            param_spans.insert(span_id);
                        }
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

            if param_num == 0 {
                spans = param_spans;
            } else if spans.intersect(param_spans) {
                return Ok(Vec::new());
            }
        }

        Ok(spans.into_vec())

*/
