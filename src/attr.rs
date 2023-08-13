use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

pub trait StunAttrValue<'i> {
	fn length(&self) -> u16;
	fn encode(&self, buff: &mut [u8], xor_bytes: &[u8; 16], pieces: &[&[u8]]);
	fn decode(buff: &'i [u8], xor_bytes: &[u8; 16], pieces: &[&[u8]]) -> Option<Self> where Self: Sized;
}

impl StunAttrValue<'static> for SocketAddr {
	fn length(&self) -> u16 {
		match self {
			Self::V4(_) => 8,
			Self::V6(_) => 20,
		}
	}
	fn encode(&self, buff: &mut [u8], xor_bytes: &[u8; 16], _: &[&[u8]]) {
		buff[0] = 0;
		let family = if self.is_ipv4() { 0x01 } else { 0x02 };
		buff[1] = family;
		let port = self.port().to_be_bytes();
		let xport: [u8; 2] = std::array::from_fn(|i| port[i] ^ xor_bytes[i]);
		buff[2..][..2].copy_from_slice(&xport);
		match self.ip() {
			IpAddr::V4(ip) => {
				let octs = ip.octets();
				let xocts: [u8; 4] = std::array::from_fn(|i| octs[i] ^ xor_bytes[i]);
				buff[4..][..4].copy_from_slice(&xocts)
			},
			IpAddr::V6(ip) => {
				let octs = ip.octets();
				let xocts: [u8; 16] = std::array::from_fn(|i| octs[i] ^ xor_bytes[i]);
				buff[4..][..16].copy_from_slice(&xocts);
			}
		}
	}
	fn decode(buff: &[u8], xor_bytes: &[u8; 16], _: &[&[u8]]) -> Option<Self> {
		if buff.len() < 8 { return None }

		let family = buff[1];
		let xport = &buff[2..][..2];
		let port = u16::from_be_bytes(std::array::from_fn(|i| xport[i] ^ xor_bytes[i]));
		
		let xip = &buff[4..];
		let ip = match (family, xip.len()) {
			(0x01, 4) => Ipv4Addr::from(std::array::from_fn(|i| xip[i] ^ xor_bytes[i])).into(),
			(0x02, 16) => Ipv6Addr::from(std::array::from_fn(|i| xip[i] ^ xor_bytes[i])).into(),
			_ => return None
		};
		Some(SocketAddr::new(ip, port))
	}
}
impl StunAttrValue<'static> for () {
	fn length(&self) -> u16 {
		0
	}
	fn encode(&self, _: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {}
	fn decode(buff: &[u8], _: &[u8; 16], _: &[&[u8]]) -> Option<Self> {
		if buff.len() == 0 {
			Some(())
		} else {
			None
		}
	}
}
impl<'i> StunAttrValue<'i> for &'i str {
	fn length(&self) -> u16 {
		self.len() as u16
	}
	fn encode(&self, buff: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {
		buff.copy_from_slice(self.as_bytes())
	}
	fn decode(buff: &'i [u8], _: &[u8; 16], _: &[&[u8]]) -> Option<Self> {
		std::str::from_utf8(buff).ok()
	}
}
impl<'i> StunAttrValue<'i> for &'i [u8] {
	fn length(&self) -> u16 {
		self.len() as u16
	}
	fn encode(&self, buff: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {
		buff.copy_from_slice(self)
	}
	fn decode(buff: &'i [u8], _: &[u8; 16], _: &[&[u8]]) -> Option<Self> {
		Some(buff)
	}
}
impl<'i, const N: usize> StunAttrValue<'i> for &'i [u8; N] {
	fn length(&self) -> u16 {
		N as u16
	}
	fn encode(&self, buff: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {
		buff.copy_from_slice(self.as_slice())
	}
	fn decode(buff: &'i [u8], _: &[u8; 16], _: &[&[u8]]) -> Option<Self> where Self: Sized {
		buff.try_into().ok()
	}
}
impl StunAttrValue<'static> for u32 {
	fn length(&self) -> u16 {
		self.to_be_bytes().len() as u16
	}
	fn encode(&self, buff: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {
		buff.copy_from_slice(&self.to_be_bytes())
	}
	fn decode(buff: &[u8], _: &[u8; 16], _: &[&[u8]]) -> Option<Self> {
		buff.try_into().ok().map(Self::from_be_bytes)
	}
}
impl StunAttrValue<'static> for u64 {
	fn length(&self) -> u16 {
		self.to_be_bytes().len() as u16
	}
	fn encode(&self, buff: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {
		buff.copy_from_slice(&self.to_be_bytes())
	}
	fn decode(buff: &[u8], _: &[u8; 16], _: &[&[u8]]) -> Option<Self> {
		buff.try_into().ok().map(Self::from_be_bytes)
	}
}
#[derive(Debug, Clone)]
pub struct Error<'i> {
	code: u16,
	message: &'i str
}
impl<'i> StunAttrValue<'i> for Error<'i> {
	fn length(&self) -> u16 {
		4 + self.message.len() as u16
	}
	fn decode(buff: &'i [u8], xor_bytes: &[u8; 16], pieces: &[&[u8]]) -> Option<Self> {
		if buff.len() < 4 { return None }

		let code = (buff[2] * 100) as u16 + buff[3] as u16;
		let message = std::str::from_utf8(&buff[4..]).unwrap_or("");
		Some(Self { code, message })
	}
	fn encode(&self, buff: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {
		buff[0] = 0;
		buff[1] = 0;
		buff[2] = (self.code / 100) as u8;
		buff[3] = (self.code % 100) as u8;
		buff[4..].copy_from_slice(self.message.as_bytes());
	}
}

#[derive(Debug, Clone)]
pub enum UnknownAttributes<'i> {
	Parse(&'i [u8]),
	List(&'i [u16])
}
impl<'i> StunAttrValue<'i> for UnknownAttributes<'i> {
	fn length(&self) -> u16 {
		match self {
			Self::Parse(s) => s.len() as u16,
			Self::List(l) => (l.len() * 2) as u16
		}
	}
	fn encode(&self, mut buff: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {
		match self {
			Self::Parse(s) => buff.copy_from_slice(s),
			Self::List(l) => {
				for n in l.iter() {
					buff[..2].copy_from_slice(&n.to_be_bytes());
					buff = &mut buff[2..];
				}
			}
		}
	}
	fn decode(buff: &'i [u8], _: &[u8; 16], _: &[&[u8]]) -> Option<Self> {
		if buff.len() % 2 != 0 { return None }
		Some(Self::Parse(buff))
	}
}
#[derive(Debug, Clone)]
pub struct EvenPort(bool);
impl StunAttrValue<'static> for EvenPort {
	fn length(&self) -> u16 {
		1
	}
	fn decode(buff: &'static [u8], _: &[u8; 16], _: &[&[u8]]) -> Option<Self> where Self: Sized {
		if buff.len() != 1 { return None }
		Some(Self(buff[0] & 0b1_0000000 != 0))
	}
	fn encode(&self, buff: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {
		buff[0] = match self.0 {
			true => 0b1_0000000,
			false => 0
		};
	}
}
#[derive(Debug, Clone)]
pub struct RequestedTransport(u8);
impl StunAttrValue<'static> for RequestedTransport {
	fn length(&self) -> u16 {
		4
	}
	fn decode(buff: &'static [u8], _: &[u8; 16], _: &[&[u8]]) -> Option<Self> where Self: Sized {
		if buff.len() != 4 { return None }
		Some(Self(buff[0]))
	}
	fn encode(&self, buff: &mut [u8], _: &[u8; 16], _: &[&[u8]]) {
		buff[0] = self.0;
		buff[1] = 0;
		buff[2] = 0;
		buff[3] = 0;
	}
}

#[derive(Debug, Clone)]
pub enum StunAttr<'i> {
	// RFC 5389:
	/* 0x0001 */ Mapped(SocketAddr),
	/* 0x0006 */ Username(&'i str),
	/* 0x0008 */ Integrity(&'i [u8; 20]),
	/* 0x0009 */ Error(Error<'i>),
	/* 0x000A */ UnknownAttributes(UnknownAttributes<'i>),
	/* 0x0014 */ Realm(&'i str),
	/* 0x0015 */ Nonce(&'i str),
	/* 0x0020 */ XMapped(SocketAddr),
	/* 0x8022 */ Software(&'i str),
	/* 0x8023 */ AlternateServer(SocketAddr),
	/* 0x8028 */ Fingerprint(u32),

	// RFC 5766:
	/* 0x000C */ Channel(u32),
	/* 0x000D */ Lifetime(u32),
	/* 0x0012 */ XPeer(SocketAddr),
	/* 0x0013 */ Data(&'i [u8]),
	/* 0x0016 */ XRelayed(SocketAddr),
	/* 0x0018 */ EvenPort(EvenPort),
	/* 0x0019 */ RequestedTransport(RequestedTransport),
	/* 0x001A */ DontFragment,
	/* 0x0022 */ ReservationToken(u32),

	// RFC 5245 / 8445:
	/* 0x0024 */ Priority(u32),
	/* 0x0025 */ UseCandidate,
	/* 0x8029 */ IceControlled(u64),
	/* 0x802A */ IceControlling(u64),

	Other(u16, &'i [u8]),
}
impl<'i> StunAttr<'i> {
	pub fn typ(&self) -> u16 {
		match self {
			Self::Mapped(_) => 0x0001,
			Self::Username(_) => 0x0006,
			Self::Integrity(_) => 0x0008,
			Self::Error(_) => 0x0009,
			Self::UnknownAttributes(_) => 0x000A,
			Self::Realm(_) => 0x0014,
			Self::Nonce(_) => 0x0015,
			Self::XMapped(_) => 0x0020,
			Self::Software(_) => 0x8028,
			Self::AlternateServer(_) => 0x8023,
			Self::Fingerprint(_) => 0x8028,
			Self::Channel(_) => 0x000C,
			Self::Lifetime(_) => 0x000D,
			Self::XPeer(_) => 0x0012,
			Self::Data(_) => 0x0013,
			Self::XRelayed(_) => 0x0016,
			Self::EvenPort(_) => 0x0018,
			Self::RequestedTransport(_) => 0x0019,
			Self::DontFragment => 0x001A,
			Self::ReservationToken(_) => 0x0022,
			Self::Priority(_) => 0x0024,
			Self::UseCandidate => 0x0025,
			Self::IceControlled(_) => 0x8029,
			Self::IceControlling(_) => 0x802A,
			Self::Other(typ, _) => *typ
		}
	}
	pub fn value(&self) -> &dyn StunAttrValue {
		match self {
			Self::DontFragment | Self::UseCandidate => &(),
			Self::Mapped(v) => v,
			Self::Username(v) => v,
			Self::Integrity(v) => v,
			Self::Error(v) => v,
			Self::UnknownAttributes(v) => v,
			Self::Realm(v) => v,
			Self::Nonce(v) => v,
			Self::XMapped(v) => v,
			Self::Software(v) => v,
			Self::AlternateServer(v) => v,
			Self::Fingerprint(v) => v,
			Self::Channel(v) => v,
			Self::Lifetime(v) => v,
			Self::XPeer(v) => v,
			Self::Data(v) => v,
			Self::XRelayed(v) => v,
			Self::EvenPort(v) => v,
			Self::RequestedTransport(v) => v,
			Self::ReservationToken(v) => v,
			Self::Priority(v) => v,
			Self::IceControlled(v) => v,
			Self::IceControlling(v) => v,
			Self::Other(_, v) => v
		}
	}
	pub fn length(&self) -> u16 {
		self.value().length()
	}
}
