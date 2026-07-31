//! Shared bounded framing for enrollment messages carried inside the WSS relay.
//!
//! The managed relay forwards opaque binary frames. These helpers frame the
//! application messages inside the end-to-end stream; they contain no broker,
//! listener, raw-socket compatibility path, or deployment behavior.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TOKEN_LEN: usize = 32;
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

pub(crate) async fn write_frame<W>(stream: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if bytes.len() > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame exceeds MAX_FRAME_SIZE",
        ));
    }
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(bytes);
    stream.write_all(&framed).await?;
    stream.flush().await
}

pub(crate) async fn read_frame<R>(stream: &mut R) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer claimed a frame larger than MAX_FRAME_SIZE",
        ));
    }
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// Bind the complete session label into fixed-width opaque relay metadata.
pub(crate) fn token_bytes(label: &str) -> [u8; TOKEN_LEN] {
    use sha2::{Digest, Sha256};
    Sha256::digest(label.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_oversized_claim_is_rejected_before_allocation() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let error = read_frame(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn writing_an_oversized_frame_is_refused() {
        let (mut writer, _reader) = tokio::io::duplex(16);
        let bytes = vec![0u8; MAX_FRAME_SIZE + 1];
        let error = write_frame(&mut writer, &bytes).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn route_tokens_bind_the_entire_label() {
        let prefix = "0123456789abcdef0123456789abcdef";
        assert_ne!(
            token_bytes(&format!("{prefix}-one")),
            token_bytes(&format!("{prefix}-two")),
        );
    }
}
