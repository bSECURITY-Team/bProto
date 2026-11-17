//! Private local IPC used by the existing mTLS agent, never a remote admin API.
//! Commands contain no credentials. Only user-table changes are reloadable.

use crate::config::ServerConfig;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use vpn_core::{ServerNode, auth::config_receipt, config::to_hex};

fn immutable_config(mut config: ServerConfig) -> anyhow::Result<String> {
    config.users.clear();
    Ok(toml::to_string(&config)?)
}

/// Bind in a private, operator-created directory. Refuse active sockets and
/// non-socket paths; remove only an inactive socket in that private directory.
pub async fn bind(path: &std::path::Path) -> anyhow::Result<UnixListener> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("control directory missing"))?;
    let meta = std::fs::metadata(parent)?;
    if meta.permissions().mode() & 0o022 != 0 {
        anyhow::bail!("control directory must not be writable by group/others");
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            anyhow::bail!("control path is not a socket");
        }
        match UnixStream::connect(path).await {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(path)?
            }
            _ => anyhow::bail!("control socket already active or inaccessible"),
        }
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serial local reload/health operations. Exact applied bytes are authenticated
/// with the existing tag key; immutable deployment settings cannot be reloaded.
pub async fn serve(
    listener: UnixListener,
    path: PathBuf,
    initial: ServerConfig,
    node: Arc<ServerNode>,
) -> anyhow::Result<()> {
    let immutable = immutable_config(initial.clone())?;
    let key = initial.tag_key_bytes()?;
    let mut receipt = config_receipt(&key, &std::fs::read(&path)?);
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut command = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let byte = stream.read_u8().await?;
                if byte == b'\n' {
                    return Ok::<(), std::io::Error>(());
                }
                command.push(byte);
                if command.len() > 16 {
                    return Err(std::io::Error::other("command too long"));
                }
            }
        })
        .await;
        if !matches!(read, Ok(Ok(()))) {
            continue;
        }
        let response = match command.as_slice() {
            b"health" => format!("ok {}\n", to_hex(&receipt)),
            b"reload" => {
                let result = async {
                    let bytes = std::fs::read(&path)?;
                    let config: ServerConfig = toml::from_str(std::str::from_utf8(&bytes)?)?;
                    config.validate()?;
                    if immutable_config(config.clone())? != immutable {
                        anyhow::bail!("only credentials may change");
                    }
                    node.replace_tags(config.tag_table()?).await?;
                    receipt = config_receipt(&key, &bytes);
                    Ok::<(), anyhow::Error>(())
                }
                .await;
                if result.is_ok() {
                    format!("ok {}\n", to_hex(&receipt))
                } else {
                    "error reload rejected\n".into()
                }
            }
            _ => "error unknown command\n".into(),
        };
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            stream.write_all(response.as_bytes()),
        )
        .await;
    }
}
