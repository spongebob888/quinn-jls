use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use proto::{ConnectionError, EcnCodepoint, Transmit};
use tracing::debug;
use udp::RecvMeta;

use crate::{udp_transmit, AsyncUdpSocket, Runtime, UdpSender, endpoint::respond};

const RATE_LIMIT_CYCLE: Duration = Duration::from_millis(10); // 10ms

pub(crate) fn bind_upstream_socket(
    upstream_addr: &str,
) -> Result<(std::net::UdpSocket, SocketAddr), ConnectionError> {
    let upstream_addr: SocketAddr = upstream_addr
        .to_socket_addrs()
        .map_err(|x| ConnectionError::JlsForwardError(x.to_string()))?
        .next()
        .ok_or(ConnectionError::JlsForwardError(
            "jls upstream domain name resolved failed".into(),
        ))?;
    let bind_addr = if upstream_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = std::net::UdpSocket::bind(bind_addr.parse::<SocketAddr>().unwrap())
        .map_err(|x| ConnectionError::JlsForwardError(x.to_string()))?;
    Ok((socket, upstream_addr))
}
pub(crate) fn insert_forward_conn(
    jls_state: &mut JlsState,
    runtime: &dyn Runtime,
    trans: Vec<Transmit>,
    response_buffer: &[u8],
    upstream_addr: &str,
    remote_addr: SocketAddr,
    now: Instant,
) -> Result<(), ConnectionError> {
    let (socket, upstream_addr) = bind_upstream_socket(upstream_addr)?;
    debug!("new forward connection:transmit:{}", trans.len());

    let udp_socket = runtime.wrap_udp_socket(socket).unwrap();
    let mut udp_sender = udp_socket.create_sender();
    let recv_buf = vec![0; 32 * 32 * 1024]; // 
    let byte_per_cycle = jls_state
        .rate_bps
        .min(u64::MAX / RATE_LIMIT_CYCLE.as_millis() as u64)
        * RATE_LIMIT_CYCLE.as_millis() as u64
        / (1000 * 8/* 8 bits per byte */);
    let byte_per_cycle = byte_per_cycle.min(usize::MAX as u64) as usize;
    let jls_conn: JlsForwardConnection = JlsForwardConnection {
        upstream_socket: udp_socket,
        upstream_addr: upstream_addr,
        from_upstream: recv_buf.into(),
        active_time: now.clone(),
        send_limiter: JlsRateLimiter::new(RATE_LIMIT_CYCLE, byte_per_cycle as usize), // 128K per second
        recv_limiter: JlsRateLimiter::new(RATE_LIMIT_CYCLE, byte_per_cycle as usize), // 128K per second
    };

    // The forward socket was created just above, so the async runtime has not
    // registered it with the I/O driver yet: a fire-and-forget `poll_send` with a
    // noop waker (as `endpoint::respond` uses for stateless responses on an
    // already-registered socket) returns `Poll::Pending` on the very first poll
    // and silently drops the datagram. Spawn the initial forwards as an async
    // task that awaits writability with a real waker before sending.
    let buf = response_buffer.to_vec();
    if !trans.is_empty() {
        let mut pos = 0;
        runtime.spawn(Box::pin(async move {
            for mut tr in trans {
                tr.destination = upstream_addr;
                let transmit = udp_transmit(&tr, &buf[pos..pos + tr.size]);
                tracing::trace!("initial jls forward to upstream {} bytes", tr.size);
                let _ =
                    std::future::poll_fn(|cx| udp_sender.as_mut().poll_send(&transmit, cx)).await;
                pos += tr.size;
            }
        }));
    }

    jls_state.upstream_connections.insert(remote_addr, jls_conn);
    Ok(())
}

#[derive(Debug)]
pub(crate) struct JlsForwardConnection {
    pub(crate) upstream_socket: Box<dyn AsyncUdpSocket>,
    pub(crate) upstream_addr: SocketAddr,
    pub(crate) from_upstream: Box<[u8]>,
    pub(crate) active_time: Instant,
    pub(crate) send_limiter: JlsRateLimiter,
    pub(crate) recv_limiter: JlsRateLimiter,
}

#[derive(Debug, Default)]
pub(crate) struct JlsState {
    pub(crate) upstream_connections: HashMap<SocketAddr, JlsForwardConnection>,
    pub(crate) rate_bps: u64,
}

impl JlsState {
    pub(crate) fn new(rate_bps: u64) -> Self {
        Self {
            upstream_connections: HashMap::new(),
            rate_bps,
        }
    }
    pub(crate) fn handle_jls_forward(
        &mut self,
        buf: &BytesMut,
        meta: &RecvMeta,
        now: Instant,
    ) -> bool {
        // let segment_size = if meta.stride < meta.len {
        //     Some(meta.stride)
        // } else {
        //     None
        // };
        match self.upstream_connections.get_mut(&meta.addr) {
            Some(conn) => {
                let trans = Transmit {
                    destination: conn.upstream_addr,
                    ecn: meta.ecn.map(|x| EcnCodepoint::from_bits(x as u8).unwrap()),
                    segment_size: None,
                    size: buf.len(),
                    src_ip: None,
                };
                conn.active_time = now;
                tracing::trace!("jls forward to upstream {} bytes", trans.size);
                conn.send_limiter.try_send(
                    buf,
                    trans,
                    &mut conn.upstream_socket.create_sender(),
                    now,
                );

                true
            }
            None => false,
        }
    }
}

// fn respond(transmit: proto::Transmit, response_buffer: &[u8], socket: &dyn AsyncUdpSocket) {
//     // Send if there's kernel buffer space; otherwise, drop it
//     //
//     // As an endpoint-generated packet, we know this is an
//     // immediate, stateless response to an unconnected peer,
//     // one of:
//     //
//     // - A version negotiation response due to an unknown version
//     // - A `CLOSE` due to a malformed or unwanted connection attempt
//     // - A stateless reset due to an unrecognized connection
//     // - A `Retry` packet due to a connection attempt when
//     //   `use_retry` is set
//     //
//     // In each case, a well-behaved peer can be trusted to retry a
//     // few times, which is guaranteed to produce the same response
//     // from us. Repeated failures might at worst cause a peer's new
//     // connection attempt to time out, which is acceptable if we're
//     // under such heavy load that there's never room for this code
//     // to transmit. This is morally equivalent to the packet getting
//     // lost due to congestion further along the link, which
//     // similarly relies on peer retries for recovery.
//     _ = socket.try_send(&udp_transmit(&transmit, &response_buffer[..transmit.size]));
// }

#[derive(Debug)]
pub(crate) struct JlsRateLimiter {
    last_cycle: Instant,
    data_handled: usize, // Data amount handled since last cycle
    cycle_period: Duration,
    pub bytes_per_cycle: usize,
}
impl JlsRateLimiter {
    pub(crate) fn new(cycle_period: Duration, bytes_per_cycle: usize) -> Self {
        Self {
            last_cycle: Instant::now(),
            data_handled: 0,
            cycle_period,
            bytes_per_cycle,
        }
    }
    pub(crate) fn should_send(&mut self, data_size: usize, now: Instant) -> bool {
        if now.duration_since(self.last_cycle) >= self.cycle_period {
            self.data_handled = 0;
            self.last_cycle = now;
        }
        if self.data_handled + data_size > self.bytes_per_cycle {
            // 128K per cycle
            return false;
        }
        self.data_handled += data_size;
        true
    }
    pub(crate) fn try_send(
        &mut self,
        buf: &[u8],
        trans: Transmit,
        sender: &mut Pin<Box<dyn UdpSender>>,
        now: Instant,
    ) -> bool {
        if self.should_send(buf.len(), now) {
            respond(trans, buf, sender);
            return true;
        }
        false
    }
}
