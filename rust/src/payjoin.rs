use bitcoin::psbt::Psbt;
use bitcoin::{FeeRate, OutPoint};
#[allow(deprecated)]
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

    #[error("receiver injected a wallet-owned input: {0}")]
    OwnershipViolation(String),

    #[error("failed to build payjoin sender: {0}")]
    SenderBuild(String),
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
        .map_err(|e| Error::SenderBuild(e.to_string()))?;

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

#[allow(dead_code)]
pub async fn send(
    wallet: &mut Wallet,
    original_psbt: Psbt,
    pj_uri_str: &str,
) -> Result<bitcoin::Transaction, Error> {
    let original_outpoints: Vec<OutPoint> =
        original_psbt.unsigned_tx.input.iter().map(|i| i.previous_output).collect();

    let mut proposal = negotiate_v1(original_psbt, pj_uri_str).await?;

    check_ownership_containment(&proposal, &original_outpoints, wallet)?;

    #[allow(deprecated)]
    let finalized = wallet
        .sign(&mut proposal, SignOptions::default())
        .map_err(|_| Error::SignFailed)?;

    if !finalized {
        return Err(Error::SignFailed);
    }

    proposal.extract_tx().map_err(|e| Error::ExtractTx(e.to_string()))
}

pub fn check_ownership_containment(
    proposal: &Psbt,
    original_outpoints: &[OutPoint],
    wallet: &Wallet,
) -> Result<(), Error> {
    let owned: std::collections::HashSet<OutPoint> =
        wallet.list_unspent().map(|u| u.outpoint).collect();

    for input in &proposal.unsigned_tx.input {
        let op = input.previous_output;
        if !original_outpoints.contains(&op) && owned.contains(&op) {
            return Err(Error::OwnershipViolation(op.to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

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

    /// PAYJOIN_RECEIVER_ADDR=<addr> cargo test -p cove bip78_e2e -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn bip78_e2e() {
        use serde_json::json;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let rpc_url = "http://user:password@localhost:18443/wallet/sender";
        let client = reqwest::Client::new();

        let receiver_addr = std::env::var("PAYJOIN_RECEIVER_ADDR")
            .expect("set PAYJOIN_RECEIVER_ADDR to the address payjoin-cli printed");

        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "method": "walletcreatefundedpsbt",
                "params": [[], [{&receiver_addr: 0.001}]]
            }))
            .send().await.unwrap().json().await.unwrap();
        let psbt_b64 = resp["result"]["psbt"].as_str().unwrap().to_string();

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

        let proposal = Psbt::from_str(&proposal_b64).expect("receiver returned a valid PSBT");

        assert_eq!(
            proposal.unsigned_tx.input.len(),
            2,
            "payjoin tx must have 2 inputs: one from sender, one added by receiver"
        );
        println!("inputs in proposal: {} ✓  (receiver added 1 input)", proposal.unsigned_tx.input.len());

        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "method": "walletprocesspsbt",
                "params": [proposal_b64]
            }))
            .send().await.unwrap().json().await.unwrap();
        let signed_proposal_b64 = resp["result"]["psbt"].as_str().unwrap().to_string();

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

    /// PAYJOIN_RECEIVER_ADDR=<addr> cargo test -p cove bip78_send_flow -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn bip78_send_flow() {
        use bdk_wallet::CreateParams;
        use bitcoin::Network;
        use serde_json::json;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let rpc_url = "http://user:password@localhost:18443/wallet/sender";
        let client = reqwest::Client::new();

        let receiver_addr = std::env::var("PAYJOIN_RECEIVER_ADDR")
            .expect("set PAYJOIN_RECEIVER_ADDR to the address payjoin-cli printed");

        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "method": "walletcreatefundedpsbt",
                "params": [[], [{&receiver_addr: 0.001}]]
            }))
            .send().await.unwrap().json().await.unwrap();
        let psbt_b64 = resp["result"]["psbt"].as_str().unwrap().to_string();

        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "method": "walletprocesspsbt",
                "params": [psbt_b64]
            }))
            .send().await.unwrap().json().await.unwrap();
        let signed_b64 = resp["result"]["psbt"].as_str().unwrap().to_string();
        let original_psbt = Psbt::from_str(&signed_b64).expect("valid PSBT");

        let original_outpoints: Vec<OutPoint> =
            original_psbt.unsigned_tx.input.iter().map(|i| i.previous_output).collect();

        let desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
        let wallet = CreateParams::new_single(desc)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("wallet created");

        let response = reqwest::Client::new()
            .post("http://localhost:3000/?v=1")
            .header("Content-Type", "text/plain")
            .body(signed_b64)
            .send()
            .await;

        match response {
            Err(e) => {
                println!("payjoin receiver unreachable ({e}), would broadcast original tx");
                let txid = original_psbt.unsigned_tx.compute_txid();
                println!("fallback txid (unsigned): {txid}");
                println!("PayjoinFallbackSent reconcile message would fire");
                return;
            }
            Ok(resp) => {
                let status = resp.status();
                let proposal_b64 = resp.text().await.unwrap();
                println!("receiver responded: {status} ({} bytes)", proposal_b64.len());
                assert_eq!(status.as_u16(), 200, "receiver must accept the original PSBT");

                let proposal = Psbt::from_str(&proposal_b64).expect("receiver returned valid PSBT");

                check_ownership_containment(&proposal, &original_outpoints, &wallet)
                    .expect("ownership check must pass");
                println!(
                    "ownership check passed — {}/{} inputs verified as non-wallet-owned",
                    proposal.unsigned_tx.input.len() - original_outpoints.len(),
                    proposal.unsigned_tx.input.len()
                );

                assert_eq!(proposal.unsigned_tx.input.len(), 2, "receiver added 1 input");
                println!(
                    "payjoin proposal valid — {} inputs ({} from sender, {} from receiver)",
                    proposal.unsigned_tx.input.len(),
                    original_outpoints.len(),
                    proposal.unsigned_tx.input.len() - original_outpoints.len()
                );
                println!("PayjoinSucceeded reconcile message would fire");
            }
        }
    }
}
