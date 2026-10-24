#![cfg(test)]

use std::{
    io::{self, Write},
    net::ToSocketAddrs,
    sync::Arc,
    time::Duration,
    u32::MAX,
};

use anyhow::{Context, Result, anyhow, bail};
use quinn::{
    ClientConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    jls::{JlsClientConfig, JlsServerConfig},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tracing::{Instrument, error, info, info_span};
async fn handle_connection(resp: String, conn: quinn::Incoming) -> Result<()> {
    let connection = conn.await?;
    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        loop {
            let stream = connection.accept_bi().await;
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            let fut = handle_request(resp.clone(), stream);
            tokio::spawn(
                async move {
                    if let Err(e) = fut.await {
                        error!("failed: {reason}", reason = e.to_string());
                    }
                }
                .instrument(info_span!("request")),
            );
        }
    }
    .instrument(span)
    .await?;
    Ok(())
}

async fn handle_request(
    rsp: String,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;

    // Write the response
    send.write_all(rsp.as_bytes()).await;
    send.write_all(&req)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;
    // Gracefully terminate the stream
    send.finish().unwrap();
    info!("complete");
    Ok(())
}

async fn make_server(resp: String, port: u16) -> Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert = cert.cert.into();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())?;
    server_crypto.jls_config = JlsServerConfig::new("123".into(), "123".into(), 
    Some("codepen.io:443".into()), None).into();
    server_crypto.max_early_data_size = std::u32::MAX;

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

    let endpoint = quinn::Endpoint::server(
        server_config,
        format!("127.0.0.1:{}", port)
            .to_socket_addrs()?
            .next()
            .unwrap(),
    )?;
    eprintln!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
        info!("accepting connection");
        let fut = handle_connection(resp.clone(), conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }
    Ok(())
}

async fn make_client(
    client_crypto: rustls::ClientConfig,
    port: usize,
    zero_rtt: bool,
) -> Result<()> {
    let host = "codepen.io";
    let remote = format!("{}:{}", "127.0.0.1", port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    let request = format!("test");

    eprintln!("connecting to {remote}");

    let conn = match endpoint.connect(remote, host)?.into_0rtt() {
        Ok((conn)) => {
            let accepted = conn.clone();
            tokio::spawn(async move {
                assert!(accepted.authenticated().await.is_ok());
                info!("0-RTT data accepted");
            });
            conn
        }
        Err(conn) => {
            assert!(zero_rtt == false);
            conn.await?
        }
    };

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;

    send.write_all(request.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to send request: {}", e))?;

    send.finish().unwrap();

    let resp = recv
        .read_to_end(usize::MAX)
        .await
        .map_err(|e| anyhow!("failed to read response: {}", e))?;
    info!("max_datagran_size:{:?}", conn.max_datagram_size());

    assert!(resp == b"jls_server:test");
    info!("jls authed:{:?}", conn.is_jls());
    assert!(conn.is_jls() == Some(true));
    io::stdout().write_all(&resp).unwrap();
    io::stdout().flush().unwrap();
    conn.close(0u32.into(), b"done");

    // Give the server a fair chance to receive the close packet
    endpoint.wait_idle().await;
    Ok(())
}
#[test]
fn jls_success() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap_or_default();

    // env_logger::init();
    let mut roots = rustls::RootCertStore::empty();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.enable_early_data = true;
    client_crypto.jls_config = JlsClientConfig::new("123", "123");

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let h1 = tokio::spawn(async {
                let h1 = make_server("jls_server:".into(), 4443).await.unwrap();
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            make_client(client_crypto.clone(), 4443, false)
                .await
                .unwrap();
            make_client(client_crypto, 4443, true).await.unwrap();
            tokio::time::sleep(Duration::from_millis(2000)).await;
        });

    ()
}
