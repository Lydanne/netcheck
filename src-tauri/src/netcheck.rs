use chrono::{DateTime, Utc};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tauri_plugin_http::reqwest;
use thiserror::Error;
use tokio_rustls::TlsConnector;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
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

/// 检查域名是否可达
#[tauri::command]
pub async fn check_connectivity(domain: String) -> Result<ConnectivityResult, String> {
    let client = reqwest::Client::new();
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

/// 检查域名DNS解析结果
#[tauri::command]
pub async fn check_dns(domain: String) -> Result<DnsResult, String> {
    // 创建解析器配置
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;

    // 使用系统配置创建解析器
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

    let mut dns_result = DnsResult {
        a_records: Vec::new(),
        aaaa_records: Vec::new(),
        ns_records: Vec::new(),
        mx_records: Vec::new(),
        txt_records: Vec::new(),
    };

    // 并行查询所有记录类型
    let (ip_result, ns_result, mx_result, txt_result) = tokio::join!(
        resolver.lookup_ip(&domain),
        resolver.ns_lookup(&domain),
        resolver.mx_lookup(&domain),
        resolver.txt_lookup(&domain)
    );

    // 处理 A 和 AAAA 记录
    if let Ok(lookup) = ip_result {
        dns_result.a_records = lookup
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| ip.to_string())
            .collect();
        dns_result.aaaa_records = lookup
            .iter()
            .filter(|ip| ip.is_ipv6())
            .map(|ip| ip.to_string())
            .collect();
    }

    // 处理 NS 记录
    if let Ok(lookup) = ns_result {
        dns_result.ns_records = lookup.iter().map(|ns| ns.to_string()).collect();
    }

    // 处理 MX 记录
    if let Ok(lookup) = mx_result {
        dns_result.mx_records = lookup
            .iter()
            .map(|mx| format!("{} {}", mx.preference(), mx.exchange()))
            .collect();
    }

    // 处理 TXT 记录
    if let Ok(lookup) = txt_result {
        dns_result.txt_records = lookup
            .iter()
            .filter_map(|txt| {
                let data = txt.txt_data().first()?;
                Some(String::from_utf8_lossy(data).into_owned())
            })
            .collect();
    }

    Ok(dns_result)
}

/// 检查域名证书信息
#[tauri::command]
pub async fn get_certificate_info(domain: String) -> Result<CertificateInfo, String> {
    log::info!("xxxx-0");
    let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    log::info!("xxxx-1");

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    log::info!("xxxx-2");

    let connector = TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(format!("{}:443", domain))
        .await
        .map_err(|e| format!("连接失败: {}", e))?;

    log::info!("xxxx-3");

    let server_name = rustls::pki_types::ServerName::try_from(domain)
        .map_err(|e| format!("无效的服务器名称: {}", e))?;

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| e.to_string())?;

    log::info!("xxxx-4");

    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn.peer_certificates();

    log::info!("xxxx-5");

    let cert = match certs.and_then(|c| c.first()) {
        Some(cert) => cert,
        None => return Err("无法获取证书".to_string()),
    };

    let (_, cert) = X509Certificate::from_der(cert.as_ref()).map_err(|e| e.to_string())?;
    let tbs = cert.tbs_certificate;

    log::info!("xxxx-6");

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
