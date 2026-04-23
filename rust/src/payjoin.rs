use std::str::FromStr;

use bitcoin::psbt::Psbt;
use bitcoin::FeeRate;
use bdk_wallet::{SignOptions, Wallet};
use payjoin::send::v1::SenderBuilder;
use payjoin::{Uri, UriExt};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid payjoin URI: {0}")]
    InvalidUri(String),

    #[error("URI does not contain a pj= endpoint")]
    NotPayjoin,

    #[error("receiver rejected the request: {0}")]
    ReceiverRejected(String),

    #[error("proposal failed BIP78 validation: {0}")]
    InvalidProposal(String),

    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("wallet could not sign the proposal PSBT")]
    SignFailed,

    #[error("failed to extract transaction: {0}")]
    ExtractTx(String),
}

pub async fn negotiate_v1(original_psbt: Psbt, pj_uri_str: &str) -> Result<Psbt, Error> {
    let pj_uri = Uri::try_from(pj_uri_str)
        .map_err(|e| Error::InvalidUri(e.to_string()))?
        .assume_checked()
        .check_pj_supported()
        .map_err(|_| Error::NotPayjoin)?;

    let original_input_count = original_psbt.unsigned_tx.input.len();

    let sender = SenderBuilder::new(original_psbt, pj_uri)
        .build_recommended(FeeRate::BROADCAST_MIN)
        .map_err(|e| Error::InvalidUri(e.to_string()))?;

    let (req, ctx) = sender.create_v1_post_request();

    tracing::info!(endpoint = %req.url, "sending BIP78 request to receiver");

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(Error::Http)?;

    let response = client
        .post(&req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await?;

    let status = response.status();
    let body = response.bytes().await?;

    tracing::info!(status = %status, response_bytes = body.len(), "received payjoin response");

    if !status.is_success() {
        return Err(Error::ReceiverRejected(String::from_utf8_lossy(&body).to_string()));
    }

    let proposal =
        ctx.process_response(&body).map_err(|e| Error::InvalidProposal(e.to_string()))?;

    tracing::info!(
        total_inputs = proposal.unsigned_tx.input.len(),
        "proposal passed BIP78 validation — receiver added {} input(s)",
        proposal.unsigned_tx.input.len().saturating_sub(original_input_count),
    );

    Ok(proposal)
}

pub async fn send(
    wallet: &mut Wallet,
    original_psbt: Psbt,
    pj_uri_str: &str,
) -> Result<bitcoin::Transaction, Error> {
    let mut proposal = negotiate_v1(original_psbt, pj_uri_str).await?;

    let finalized = wallet
        .sign(&mut proposal, SignOptions::default())
        .map_err(|_| Error::SignFailed)?;

    if !finalized {
        return Err(Error::SignFailed);
    }

    proposal.extract_tx().map_err(|e| Error::ExtractTx(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pj_uri_is_detected() {
        let uri = "bitcoin:bc1qrmzkzmqcgatutq6nyje8t2qs3mf8t3p0qh3kl2?amount=0.001&pj=HTTPS://EXAMPLE.COM/pj";
        let parsed = Uri::try_from(uri).expect("valid URI").assume_checked();
        assert!(parsed.check_pj_supported().is_ok());
    }

    #[test]
    fn plain_bitcoin_uri_is_rejected() {
        let uri = "bitcoin:bc1qrmzkzmqcgatutq6nyje8t2qs3mf8t3p0qh3kl2?amount=0.001";
        let parsed = Uri::try_from(uri).expect("valid URI").assume_checked();
        assert!(parsed.check_pj_supported().is_err());
    }

    #[test]
    fn http_clearnet_endpoint_is_rejected() {
        let uri = "bitcoin:bc1qrmzkzmqcgatutq6nyje8t2qs3mf8t3p0qh3kl2?amount=0.001&pj=http://example.com/pj";
        assert!(Uri::try_from(uri).is_err());
    }

    /// Requires Bitcoin Core regtest on localhost:18443 (wallets: sender, receiver) and
    /// payjoin-cli receiver on port 3000. Uses raw HTTP — negotiate_v1 enforces HTTPS in prod.
    ///
    /// PAYJOIN_RECEIVER_ADDR=<addr> cargo test -p cove bip78_e2e -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn bip78_e2e() {
        use serde_json::json;

        // rustls needs a crypto provider installed before any HTTP calls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let rpc_url = "http://user:password@localhost:18443/wallet/sender";
        let client = reqwest::Client::new();

        let receiver_addr = std::env::var("PAYJOIN_RECEIVER_ADDR")
            .expect("set PAYJOIN_RECEIVER_ADDR to the address payjoin-cli printed");

        // build funded PSBT
        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "method": "walletcreatefundedpsbt",
                "params": [[], [{&receiver_addr: 0.001}]]
            }))
            .send().await.unwrap().json().await.unwrap();
        let psbt_b64 = resp["result"]["psbt"].as_str().unwrap().to_string();

        // sign original PSBT
        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "method": "walletprocesspsbt",
                "params": [psbt_b64]
            }))
            .send().await.unwrap().json().await.unwrap();
        let signed_b64 = resp["result"]["psbt"].as_str().unwrap().to_string();

        println!("original PSBT ready — sending BIP78 request to payjoin-cli receiver");

        // POST to payjoin-cli receiver (raw HTTP — local testing only)
        let response = reqwest::Client::new()
            .post("http://localhost:3000/?v=1")
            .header("Content-Type", "text/plain")
            .body(signed_b64)
            .send()
            .await
            .expect("payjoin-cli receiver must be running on port 3000");

        let status = response.status();
        let proposal_b64 = response.text().await.unwrap();
        println!("receiver responded: {} ({} bytes)", status, proposal_b64.len());
        assert_eq!(status.as_u16(), 200, "receiver must accept the original PSBT");

        // parse proposal — receiver added its own input
        let proposal = Psbt::from_str(&proposal_b64).expect("receiver returned a valid PSBT");

        assert_eq!(
            proposal.unsigned_tx.input.len(),
            2,
            "payjoin tx must have 2 inputs: one from sender, one added by receiver"
        );
        println!("inputs in proposal: {} ✓  (receiver added 1 input)", proposal.unsigned_tx.input.len());

        // re-sign proposal (tx structure changed, original sigs are invalid)
        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "method": "walletprocesspsbt",
                "params": [proposal_b64]
            }))
            .send().await.unwrap().json().await.unwrap();
        let signed_proposal_b64 = resp["result"]["psbt"].as_str().unwrap().to_string();

        // finalize and broadcast
        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "method": "finalizepsbt",
                "params": [signed_proposal_b64]
            }))
            .send().await.unwrap().json().await.unwrap();
        let raw_hex = resp["result"]["hex"].as_str().unwrap().to_string();

        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "method": "sendrawtransaction",
                "params": [raw_hex]
            }))
            .send().await.unwrap().json().await.unwrap();

        let txid = resp["result"].as_str().expect("should get a txid back");
        println!("payjoin tx broadcast: {txid}");
        println!("run: bitcoin-cli -regtest getrawtransaction {txid} true | python3 -m json.tool");
    }
}
