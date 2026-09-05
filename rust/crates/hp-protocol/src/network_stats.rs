//! Read existing socket telemetry. No packets, connections, or probes are sent.
use std::{net::TcpStream, time::Duration};

#[cfg(windows)]
pub(crate) fn network_rtt(tcp: &TcpStream) -> Option<Duration> {
    use std::{mem::size_of, os::windows::io::AsRawSocket, ptr};
    use windows_sys::Win32::Networking::WinSock::{TCP_INFO_v0, WSAIoctl, SIO_TCP_INFO};
    let version = 0u32;
    let mut info = TCP_INFO_v0::default();
    let mut returned = 0u32;
    // SAFETY: the borrowed TcpStream owns a live SOCKET for this entire call.
    // Version/input, typed output and byte-count pointers refer to initialized,
    // correctly sized stack storage. No overlapped operation is submitted, so
    // Windows cannot retain these pointers. This IOCTL reads kernel-maintained
    // statistics immediately; it does not wait for a peer response or send data.
    let status = unsafe {
        WSAIoctl(
            tcp.as_raw_socket() as usize,
            SIO_TCP_INFO,
            (&version as *const u32).cast(),
            size_of::<u32>() as u32,
            (&mut info as *mut TCP_INFO_v0).cast(),
            size_of::<TCP_INFO_v0>() as u32,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    };
    if status != 0 {
        return None;
    }
    parse_info(&info, returned)
}

#[cfg(windows)]
fn parse_info(
    info: &windows_sys::Win32::Networking::WinSock::TCP_INFO_v0,
    returned: u32,
) -> Option<Duration> {
    if (returned as usize) < std::mem::size_of_val(info) || info.RttUs == 0 {
        return None;
    }
    Some(Duration::from_micros(u64::from(info.RttUs)))
}

#[cfg(not(windows))]
pub(crate) fn network_rtt(_tcp: &TcpStream) -> Option<Duration> {
    None
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::Win32::Networking::WinSock::TCP_INFO_v0;
    #[test]
    fn preserves_microsecond_precision() {
        let info = TCP_INFO_v0 {
            RttUs: 1250,
            ..Default::default()
        };
        assert_eq!(
            parse_info(&info, std::mem::size_of_val(&info) as u32),
            Some(Duration::from_micros(1250))
        );
    }
    #[test]
    fn ignores_missing_or_truncated_statistics() {
        let mut info = TCP_INFO_v0::default();
        let size = std::mem::size_of_val(&info) as u32;
        assert_eq!(parse_info(&info, size), None);
        info.RttUs = 100;
        assert_eq!(parse_info(&info, size - 1), None);
        assert_eq!(parse_info(&info, 0), None);
    }
}
