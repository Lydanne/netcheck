use chrono::{DateTime, Utc};
use native_tls::TlsConnector;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use x509_parser::prelude::*;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("DNS解析错误: {0}")]
    DnsError(String),
    #[error("连接错误: {0}")]
    ConnectionError(String),
    #[error("证书错误: {0}")]
    CertificateError(String),
}

#[derive(Debug, Serialize)]
pub struct ConnectivityResult {
    pub is_reachable: bool,
    pub response_time_ms: u64,
    pub status_code: Option<u16>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DnsResult {
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub valid_from: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub valid_until: DateTime<Utc>,
    pub serial_number: String,
    pub version: u32,
}

#[tauri::command]
pub async fn check_connectivity(domain: String) -> Result<ConnectivityResult, String> {
    let client = Client::new();
    let url = format!("https://{}", domain);
    let start = std::time::Instant::now();

    match client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let duration = start.elapsed().as_millis() as u64;
            Ok(ConnectivityResult {
                is_reachable: true,
                response_time_ms: duration,
                status_code: Some(response.status().as_u16()),
                error: None,
            })
        }
        Err(e) => Ok(ConnectivityResult {
            is_reachable: false,
            response_time_ms: 0,
            status_code: None,
            error: Some(e.to_string()),
        }),
    }
}

#[tauri::command]
pub async fn check_dns(domain: String) -> Result<DnsResult, String> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
        .map_err(|e| e.to_string())?;

    let a_lookup = resolver.lookup_ip(&domain).map_err(|e| e.to_string())?;
    let a_records: Vec<String> = a_lookup.iter().map(|ip| ip.to_string()).collect();

    let mut dns_result = DnsResult {
        a_records,
        aaaa_records: Vec::new(),
        ns_records: Vec::new(),
        mx_records: Vec::new(),
        txt_records: Vec::new(),
    };

    // AAAA records
    if let Ok(aaaa_lookup) = resolver.ipv6_lookup(&domain) {
        dns_result.aaaa_records = aaaa_lookup.iter().map(|ip| ip.to_string()).collect();
    }

    // NS records
    if let Ok(ns_lookup) = resolver.ns_lookup(&domain) {
        dns_result.ns_records = ns_lookup.iter().map(|ns| ns.to_string()).collect();
    }

    // MX records
    if let Ok(mx_lookup) = resolver.mx_lookup(&domain) {
        dns_result.mx_records = mx_lookup
            .iter()
            .map(|mx| format!("{} {}", mx.preference(), mx.exchange()))
            .collect();
    }

    // TXT records
    if let Ok(txt_lookup) = resolver.txt_lookup(&domain) {
        dns_result.txt_records = txt_lookup
            .iter()
            .filter_map(|txt| {
                let data = txt.txt_data().first()?;
                Some(String::from_utf8_lossy(data).into_owned())
            })
            .collect();
    }

    Ok(dns_result)
}

#[tauri::command]
pub async fn get_certificate_info(domain: String) -> Result<CertificateInfo, String> {
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;

    let stream = tokio::net::TcpStream::connect(format!("{}:443", domain))
        .await
        .map_err(|e| e.to_string())?;

    let connector = tokio_native_tls::TlsConnector::from(connector);
    let tls_stream = connector
        .connect(&domain, stream)
        .await
        .map_err(|e| e.to_string())?;

    let cert = match tls_stream.get_ref().peer_certificate() {
        Ok(Some(cert)) => cert,
        Ok(None) => return Err("无法获取证书".to_string()),
        Err(e) => return Err(e.to_string()),
    };

    let cert_der = cert.to_der().map_err(|e| e.to_string())?;
    let (_, cert) = X509Certificate::from_der(&cert_der).map_err(|e| e.to_string())?;
    let tbs = cert.tbs_certificate;

    Ok(CertificateInfo {
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        valid_from: DateTime::from_timestamp(tbs.validity.not_before.timestamp(), 0)
            .ok_or_else(|| "无效的开始时间".to_string())?,
        valid_until: DateTime::from_timestamp(tbs.validity.not_after.timestamp(), 0)
            .ok_or_else(|| "无效的结束时间".to_string())?,
        serial_number: format!("{:X}", tbs.serial),
        version: tbs.version.0 as u32 + 1,
    })
}
