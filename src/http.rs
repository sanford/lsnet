//! Just enough HTTP to read a UPnP description or a web UI's banner.

use flate2::read::GzDecoder;
use serde::Serialize;
use std::io::Read;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

const MAX_BODY: usize = 64 * 1024;

pub struct Response {
    pub headers: String,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

/// HTTP/1.0 GET. Many embedded servers ignore `Connection: close` and hold the
/// socket open, so rather than read to EOF we stop once the body is complete
/// and, at the deadline, keep whatever has arrived.
pub async fn get(ip: Ipv4Addr, port: u16, path: &str, wait: Duration) -> Option<Response> {
    let deadline = Instant::now() + wait;
    let mut stream = timeout_at(deadline, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {ip}:{port}\r\nUser-Agent: lsnet\r\nConnection: close\r\n\r\n"
    );
    timeout_at(deadline, stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    while buf.len() < MAX_BODY && !complete(&buf) {
        match timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }

    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = String::from_utf8_lossy(&buf[..split]).to_string();
    let mut body = buf[split + 4..].to_vec();
    // Some embedded servers (ESP32 web UIs) send chunked gzip no matter what we ask for.
    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body = dechunk(&body);
    }
    if body.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        let _ = GzDecoder::new(&body[..]).read_to_end(&mut out);
        body = out;
    }
    Some(Response {
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

/// Whether `buf` holds a full response per its Content-Length or chunked terminator.
fn complete(buf: &[u8]) -> bool {
    let Some(split) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buf[..split]).to_ascii_lowercase();
    let body = &buf[split + 4..];
    if headers.contains("transfer-encoding: chunked") {
        return body.ends_with(b"0\r\n\r\n");
    }
    headers
        .lines()
        .find_map(|l| {
            l.strip_prefix("content-length:")?
                .trim()
                .parse::<usize>()
                .ok()
        })
        .is_some_and(|len| body.len() >= len)
}

#[derive(Clone, Serialize)]
pub struct Banner {
    pub server: Option<String>,
    pub title: Option<String>,
}

/// What a device's web UI says about itself.
pub async fn banner(ip: Ipv4Addr, port: u16, wait: Duration) -> Option<Banner> {
    let resp = get(ip, port, "/", wait).await?;
    let b = Banner {
        server: resp.header("server").map(String::from),
        title: tag(&resp.body, "title"),
    };
    (b.server.is_some() || b.title.is_some()).then_some(b)
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = data.windows(2).position(|w| w == b"\r\n") {
        let size_str = String::from_utf8_lossy(&data[..eol]);
        let Ok(size) = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        let start = eol + 2;
        if size == 0 || start >= data.len() {
            break;
        }
        let end = (start + size).min(data.len());
        out.extend_from_slice(&data[start..end]);
        data = &data[(end + 2).min(data.len())..];
    }
    out
}

/// Split `http://host:port/path` into its parts (IPv4 hosts only).
pub fn parse_url(url: &str) -> Option<(Ipv4Addr, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, "80"), |(h, p)| (h, p));
    // The path goes into the request line verbatim; a CR or space would break it.
    if path.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    Some((host.parse().ok()?, port.parse().ok()?, format!("/{path}")))
}

/// Contents of the first `<tag>…</tag>`, whitespace-collapsed and lightly unescaped.
pub fn tag(xml: &str, name: &str) -> Option<String> {
    let lower = xml.to_ascii_lowercase();
    let open = format!("<{}", name.to_ascii_lowercase());
    let start = lower.find(&open)?;
    let content_start = start + lower[start..].find('>')? + 1;
    let end = content_start + lower[content_start..].find('<')?;
    let text = xml[content_start..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        assert_eq!(
            parse_url("http://192.168.1.1:41389/rootDesc.xml"),
            Some((
                "192.168.1.1".parse().unwrap(),
                41389,
                "/rootDesc.xml".into()
            ))
        );
        assert_eq!(
            parse_url("http://10.0.0.2"),
            Some(("10.0.0.2".parse().unwrap(), 80, "/".into()))
        );
        assert_eq!(parse_url("http://10.0.0.2/a\rX-Evil: 1"), None);
    }

    #[test]
    fn dechunks() {
        assert_eq!(
            dechunk(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
            b"hello world"
        );
    }

    #[test]
    fn extracts_tags() {
        let xml =
            "<root><device><friendlyName>Den  TV &amp; more</friendlyName><Title x='1'>Hi</Title>";
        assert_eq!(tag(xml, "friendlyName").as_deref(), Some("Den TV & more"));
        assert_eq!(tag(xml, "title").as_deref(), Some("Hi"));
        assert_eq!(tag(xml, "missing"), None);
    }
}
