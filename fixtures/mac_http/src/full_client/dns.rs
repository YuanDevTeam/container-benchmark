//! Actual business-name queries prime the Core's unique reverse hints.
use super::{Target, error};
use crate::socketpair::UdpIo;
use serde_json::{Value, json};
use std::{collections::BTreeSet, io, net::Ipv4Addr, time::Duration};
use tokio_util::sync::CancellationToken;

fn question(id: u16, host: &str) -> io::Result<Vec<u8>> {
    let mut message = vec![0; 12];
    message[..2].copy_from_slice(&id.to_be_bytes());
    message[2] = 1;
    message[5] = 1;
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(error("invalid business DNS hostname"));
        }
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.extend_from_slice(&[0, 0, 1, 0, 1]);
    Ok(message)
}

fn name_end(bytes: &[u8], mut offset: usize) -> io::Result<usize> {
    for _ in 0..128 {
        let length = *bytes
            .get(offset)
            .ok_or_else(|| error("truncated DNS name"))?;
        if length == 0 {
            return Ok(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            if offset + 1 >= bytes.len() {
                return Err(error("truncated DNS name pointer"));
            }
            return Ok(offset + 2);
        }
        if length > 63 {
            return Err(error("invalid DNS label"));
        }
        offset += 1 + usize::from(length);
    }
    Err(error("DNS name exceeds bound"))
}

fn answer(bytes: &[u8], id: u16, expected: Ipv4Addr) -> io::Result<()> {
    if bytes.len() < 12
        || bytes[..2] != id.to_be_bytes()
        || bytes[2] & 0x80 == 0
        || bytes[3] & 0x0f != 0
        || u16::from_be_bytes([bytes[4], bytes[5]]) != 1
    {
        return Err(error("business DNS reply identity or status mismatch"));
    }
    let mut offset = name_end(bytes, 12)? + 4;
    let count = u16::from_be_bytes([bytes[6], bytes[7]]);
    let mut matched = false;
    for _ in 0..count {
        offset = name_end(bytes, offset)?;
        let fixed = bytes
            .get(offset..offset + 10)
            .ok_or_else(|| error("truncated business DNS RR"))?;
        let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let size = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        offset += 10;
        let data = bytes
            .get(offset..offset + size)
            .ok_or_else(|| error("truncated business DNS answer"))?;
        if kind == 1 && class == 1 && size == 4 {
            if data != expected.octets() {
                return Err(error("business DNS returned an unexpected reverse-hint IP"));
            }
            matched = true;
        }
        offset += size;
    }
    if !matched {
        return Err(error("business DNS lacks frozen IPv4 answer"));
    }
    Ok(())
}

pub(super) async fn prime(
    io: &mut UdpIo,
    targets: &[Target],
    client_ipv4: Ipv4Addr,
    stop: &CancellationToken,
    raw_reference: bool,
) -> io::Result<Value> {
    let mut seen = BTreeSet::new();
    let mut receipts = Vec::new();
    for target in targets {
        if !seen.insert((target.host.clone(), target.ipv4)) {
            continue;
        }
        let id = 61000 + receipts.len() as u16;
        let request = question(id, &target.host)?;
        tokio::select! {_ =stop.cancelled()=>return Err(error("business DNS preparation cancelled")),
        result=io.send(request)=>result?,}
        let received = tokio::select! {
            _ = stop.cancelled() => return Err(error("business DNS preparation cancelled")),
            result = tokio::time::timeout(Duration::from_secs(3), io.recv()) => result,
        };
        let (source_verified, verdict) = match received {
            Ok(Some(packet))
                if packet.source.to_string() == "198.18.0.1:53"
                    && packet.destination == std::net::SocketAddr::from((client_ipv4, 53000)) =>
            {
                let verdict = if raw_reference {
                    Ok(())
                } else {
                    answer(&packet.payload, id, target.ipv4)
                };
                (true, verdict)
            }
            Ok(Some(_)) => (false, Err(error("business DNS response source mismatch"))),
            Ok(None) => return Err(error("business DNS receiver closed")),
            Err(_) => (
                false,
                Err(error("business DNS preparation deadline expired")),
            ),
        };
        let mut receipt = json!({
            "host":target.host,"cnBranch":target.branch,
            "answer":(!raw_reference && verdict.is_ok()).then(|| target.ipv4.to_string()),
            "queryActuallySent":true,"responseSourceVerified":source_verified,
            "answerVerified":(!raw_reference).then(|| verdict.is_ok()),
        });
        if raw_reference {
            receipt["replyObserved"] = json!(verdict.is_ok());
        }
        if let Err(failure) = verdict {
            if !raw_reference {
                return Err(failure);
            }
            receipt["responseDiagnostic"] = json!(failure.to_string());
        }
        receipts.push(receipt);
    }
    if receipts.len() != 2 {
        return Err(error("two independent branch DNS witnesses required"));
    }
    let receipt_key = if raw_reference {
        "replyObserved"
    } else {
        "answerVerified"
    };
    let prepared = receipts.iter().all(|row| row[receipt_key] == true);
    let path = if raw_reference {
        "linux-real-tun"
    } else {
        "socketpair-through-Core"
    };
    Ok(
        json!({"prepared":prepared,"path":path,"businessNames":receipts,
        "excludedFromPressureDNSCount":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_and_answer_checks_are_not_configuration_only() {
        let query = question(61000, "positive.load.test").unwrap();
        let mut reply = query.clone();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 1;
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 10, 0, 0, 2]);
        assert!(answer(&reply, 61000, Ipv4Addr::new(10, 0, 0, 2)).is_ok());
        assert!(answer(&reply, 61000, Ipv4Addr::new(10, 0, 0, 3)).is_err());
        assert!(answer(&reply, 61001, Ipv4Addr::new(10, 0, 0, 2)).is_err());
    }
}
