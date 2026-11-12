use std::{io, net::UdpSocket};

/// Keep early HP pinhole-probe failures from poisoning Windows UDP receives.
/// macOS can open its media listeners only after the authenticated HP setup.
/// This changes no TCP behavior and leaves other socket errors observable.
pub(super) fn configure_media_socket(socket: &UdpSocket) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::{mem::size_of_val, os::windows::io::AsRawSocket, ptr};
        use windows_sys::Win32::Networking::WinSock::{
            WSAGetLastError, WSAIoctl, SIO_UDP_CONNRESET, SOCKET_ERROR,
        };

        let receive_resets = 0u32;
        let mut bytes_returned = 0u32;
        // SAFETY: the borrowed socket stays open; both buffers remain valid for
        // this synchronous call, which supplies no overlapped I/O or callback.
        let result = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as usize,
                SIO_UDP_CONNRESET,
                (&receive_resets as *const u32).cast(),
                size_of_val(&receive_resets) as u32,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut(),
                None,
            )
        };
        if result == SOCKET_ERROR {
            // SAFETY: read this thread's Winsock error immediately after failure.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    #[cfg(not(windows))]
    let _ = socket;
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        io::ErrorKind,
        net::{SocketAddr, UdpSocket},
        thread,
        time::{Duration, Instant},
    };

    fn closed_peer_address() -> SocketAddr {
        UdpSocket::bind("127.0.0.1:0")
            .expect("reserve a fixture port")
            .local_addr()
            .expect("read the fixture port")
    }

    fn connected_socket(peer: SocketAddr) -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind the fixture client");
        socket.connect(peer).expect("connect the fixture client");
        socket
            .set_nonblocking(true)
            .expect("make the fixture nonblocking");
        socket
    }

    fn verify_windows_reports_unreachable_peer(peer: SocketAddr) {
        let control = connected_socket(peer);
        control.send(&[0]).expect("send the baseline probe");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match control.recv(&mut [0; 32]) {
                Err(error) if error.raw_os_error() == Some(10054) => return,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "fixture did not generate an ICMP reset"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                result => panic!("unexpected baseline probe result: {result:?}"),
            }
        }
    }

    #[test]
    fn socket_survives_peer_startup_and_receives_media() {
        let peer = closed_peer_address();
        verify_windows_reports_unreachable_peer(peer);
        let socket = connected_socket(peer);
        super::configure_media_socket(&socket).expect("configure the media socket");
        socket.send(&[0]).expect("send the pre-negotiation probe");

        // Model a peer whose media listener opens after the startup probe.
        // A queued ICMP error must not abort the eventual first receive.
        let startup_deadline = Instant::now() + Duration::from_millis(150);
        let mut buffer = [0; 32];
        while Instant::now() < startup_deadline {
            match socket.recv(&mut buffer) {
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                result => panic!("UDP startup must remain pending, got {result:?}"),
            }
        }

        let server =
            UdpSocket::bind(peer).expect("fixture collision: cannot bind the released peer port");
        let payload = b"fixture-media";
        server
            .send_to(payload, socket.local_addr().expect("client address"))
            .expect("send the first media datagram");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match socket.recv(&mut buffer) {
                Ok(size) => {
                    assert_eq!(&buffer[..size], payload);
                    break;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "first media datagram was lost");
                    thread::sleep(Duration::from_millis(5));
                }
                result => panic!("media receive failed after peer startup: {result:?}"),
            }
        }
    }
}
