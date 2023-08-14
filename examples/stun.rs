use eyre::Result;
use stun_zc::{Stun, StunTyp, attr::StunAttr};

fn main() -> Result<()> {
	let sock = std::net::UdpSocket::bind("[::]:3478")?;
	let mut read_buff = [0u8; 4096];
	let mut write_buff = [0u8; 4096];
	loop {
		let (len, addr) = sock.recv_from(&mut read_buff)?;
		let res = Stun::decode(&read_buff[..len]);
		let m = match res {
			Err(e) => { eprintln!("{e:?}"); continue },
			Ok(m) => m
		};
		println!("{addr} {:?} {:?}", m.typ, m.txid);
		for a in &m {
			println!(" - {a:?}");
		}

		match m.typ {
			StunTyp::Req(0x001) => {
				let attrs = [
					// StunAttr::Mapped(addr.into()),
					StunAttr::XMapped(addr),
					StunAttr::Software("stun-zc: stun.rs"),
					StunAttr::Fingerprint
				];
				let r = m.res(&attrs);
				if r.len() > write_buff.len() { eprintln!("Response is too big for the output buffer!"); continue; }
				r.encode(&mut write_buff);
				sock.send_to(&write_buff[..r.len()], addr)?;
			},
			_ => { continue }
		}
	}
}
