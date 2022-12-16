use anyhow::Result;
use core::str;
use std::{env, net::Ipv4Addr};
use toytcp::tcp::TCP;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let addr: Ipv4Addr = args[1].parse()?;
    let port: u16 = args[2].parse()?;
    echo_server(addr, port)
}

fn echo_server(local_addr: Ipv4Addr, local_port: u16) -> Result<()> {
    let tcp = TCP::new();
    let listening_socket = tcp.listen(local_addr, local_port)?;
    dbg!("listening...");
    loop {
        let connected_sock_id = tcp.accept(listening_socket)?;
        dbg!(
            "accepted!",
            connected_sock_id.remote_addr,
            connected_sock_id.remote_port
        );

        let cloned_tcp = tcp.clone();
        std::thread::spawn(move || {
            let mut buffer = [0; 1024];
            loop {
                let nbytes = cloned_tcp.recv(connected_sock_id, &mut buffer).unwrap();

                if nbytes == 0 {
                    dbg!("closing connection...");
                    cloned_tcp.close(connected_sock_id).unwrap();
                    return;
                }

                print!("> {}", str::from_utf8(&buffer[..nbytes]).unwrap());
                cloned_tcp
                    .send(connected_sock_id, &buffer[..nbytes])
                    .unwrap();
            }
        });
    }
}
