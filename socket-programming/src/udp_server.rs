use std::net::UdpSocket;
use std::str;

pub fn serve(address: &str) -> Result<(), failure::Error> {
  let server_socket = UdpSocket::bind(address)?;
  loop {
    let mut buf = [0u8; 1024];
    // UDP socketからデータを受け取る (受け取ったデータはbufに格納)
    let (size, src) = server_socket.recv_from(&mut buf)?;
    debug!("Handing data from {}", src);
    println!("{}", str::from_utf8(&buf[..size])?);
    // 送信元に受け取ったデータをそのまま返す
    server_socket.send_to(&buf, src)?;
  }
}
