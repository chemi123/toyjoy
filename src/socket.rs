use anyhow::{Context, Ok, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol, TransportSender};
use pnet::util;
use std::collections::VecDeque;
use std::fmt::Display;
use std::net::Ipv4Addr;
use std::time::SystemTime;
use std::vec;

use crate::packet::{TCPPacket, MAX_PACKET_SIZE};
use crate::tcpflags;
use crate::tcpflags::get_bit_mask;

const SOCKET_BUFFER_SIZE: usize = 4380;

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub struct SockID {
    pub local_addr: Ipv4Addr,
    pub remote_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_port: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct SendParam {
    pub unacked_seq: u32, // 送信後まだackされてないseqの先頭
    pub next: u32,        // 次の送信
    pub window: u16,      // 送信ウィンドウサイズ
    pub initial_seq: u32, // 初期送信sequence、何に使ってるかよく分からない
}

#[derive(Clone, Copy, Debug)]
pub struct RecvParam {
    pub next: u32,        // 次受診するsequence
    pub window: u16,      // 受診ウィンドウサイズ
    pub initial_seq: u32, // 初期受診sequence, 何に使ってるかよく分からない
    pub tail: u32,        // 受診sequenceの最後尾, 何に使ってるかよく分からない
}

pub struct Socket {
    pub sock_id: SockID,
    pub send_param: SendParam,
    pub recv_param: RecvParam,
    pub status: TcpStatus,
    pub recv_buffer: Vec<u8>,

    // 再送用の送信データのキュー
    pub retransmission_queue: VecDeque<RetransmissionQueueEntry>,

    // passive openで利用
    // 接続済みソケットを保持するqueue, リスニングソケットのみ使用
    pub connection_queue: VecDeque<SockID>,

    // 自分を生成したリスニングソケット, server側の接続済みソケットのみ使用
    pub listening_socket: Option<SockID>,

    pub sender: TransportSender,
}

#[derive(Debug, PartialEq)]
pub enum TcpStatus {
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
}

#[derive(Clone, Debug)]
pub struct RetransmissionQueueEntry {
    pub packet: TCPPacket,
    pub latest_transmission_time: SystemTime,
    pub transmission_count: u8,
}

impl RetransmissionQueueEntry {
    fn new(packet: TCPPacket) -> Self {
        Self {
            packet,
            latest_transmission_time: SystemTime::now(),
            transmission_count: 1,
        }
    }
}

impl Display for TcpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpStatus::Listen => write!(f, "LISTEN"),
            TcpStatus::SynSent => write!(f, "SynSent"),
            TcpStatus::SynRcvd => write!(f, "SynRcvd"),
            TcpStatus::Established => write!(f, "Established"),
            TcpStatus::FinWait1 => write!(f, "FinWait1"),
            TcpStatus::FinWait2 => write!(f, "FinWait2"),
            TcpStatus::TimeWait => write!(f, "TimeWait"),
            TcpStatus::CloseWait => write!(f, "CloseWait"),
            TcpStatus::LastAck => write!(f, "LastAck"),
        }
    }
}

impl Socket {
    pub fn new(
        local_addr: Ipv4Addr,
        remote_addr: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
        status: TcpStatus,
    ) -> Result<Self> {
        let (sender, _) = transport::transport_channel(
            MAX_PACKET_SIZE,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        )?;

        let sock_id = SockID {
            local_addr,
            remote_addr,
            local_port,
            remote_port,
        };

        Ok(Self {
            sock_id,
            send_param: SendParam {
                unacked_seq: 0,
                initial_seq: 0,
                next: 0,
                window: SOCKET_BUFFER_SIZE as u16,
            },
            recv_param: RecvParam {
                initial_seq: 0,
                next: 0,
                window: SOCKET_BUFFER_SIZE as u16,
                tail: 0,
            },
            status,
            recv_buffer: vec![0; SOCKET_BUFFER_SIZE],
            retransmission_queue: VecDeque::new(),
            connection_queue: VecDeque::new(),
            listening_socket: None,
            sender,
        })
    }

    pub fn send_tcp_packet(
        &mut self,
        sequence: u32,
        ack: u32,
        flag: u8,
        payload: &[u8],
    ) -> Result<usize> {
        let mut tcp_packet = TCPPacket::new(payload.len());
        tcp_packet.set_src(self.sock_id.local_port);
        tcp_packet.set_dest(self.sock_id.remote_port);
        tcp_packet.set_seq(sequence);
        tcp_packet.set_data_offset(5); // 今回はオプションフィールドを使わないため、必然的に固定になる
        tcp_packet.set_flag(flag);
        tcp_packet.set_ack(ack);
        tcp_packet.set_window_size(self.recv_param.window);
        tcp_packet.set_payload(payload);
        tcp_packet.set_checksum(util::ipv4_checksum(
            &tcp_packet.packet(),
            8,   // skipword
            &[], // extra_data
            &&self.sock_id.local_addr,
            &&self.sock_id.remote_addr,
            IpNextHeaderProtocols::Tcp,
        ));

        dbg!(tcp_packet.get_seq());
        dbg!(tcp_packet.get_ack());
        dbg!(tcp_packet.get_src());
        dbg!(tcp_packet.get_dest());
        dbg!(self.sock_id);

        let sent_size = self
            .sender
            .send_to(
                tcp_packet.clone(),
                std::net::IpAddr::V4(self.sock_id.remote_addr),
            )
            .context(format!("failed to send: \n{:?}", tcp_packet))?;
        dbg!(&tcp_packet);

        if !payload.is_empty() || tcp_packet.get_flag() & get_bit_mask(tcpflags::ACK) > 0 {
            dbg!("push_back into retransmittion queue");
            dbg!(tcp_packet.get_flag());
            self.retransmission_queue
                .push_back(RetransmissionQueueEntry::new(tcp_packet));
        }

        Ok(sent_size)
    }

    pub fn get_sock_id(&self) -> SockID {
        self.sock_id
    }
}
