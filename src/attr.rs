use std::net::SocketAddr;
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub enum StunAttrs<'i> {
	Parse(&'i [u8]),
	List(Cow<'i, StunAttr<'i>>)
}

#[derive(Debug, Clone)]
pub enum UnknownAttributes<'i> {
	Parse(&'i [u8]),
	List(Cow<'i, [u16]>)
}

#[derive(Debug, Clone)]
pub enum StunAttr<'i> {
	// RFC 5389:
	/* 0x0001 */ Mapped(SocketAddr),
	/* 0x0006 */ Username(Cow<'i, str>),
	/* 0x0008 */ Integrity(Cow<'i, [u8; 20]>),
	/* 0x0009 */ Error { code: u16, message: Cow<'i, str> },
	/* 0x000A */ UnknownAttributes(UnknownAttributes<'i>),
	/* 0x0014 */ Realm(Cow<'i, str>),
	/* 0x0015 */ Nonce(Cow<'i, str>),
	/* 0x0020 */ XMapped(SocketAddr),
	/* 0x8022 */ Software(Cow<'i, str>),
	/* 0x8023 */ AlternateServer(SocketAddr),
	/* 0x8028 */ Fingerprint(u32),

	// RFC 5766:
	/* 0x000C */ Channel(u32),
	/* 0x000D */ Lifetime(u32),
	/* 0x0012 */ XPeer(SocketAddr),
	/* 0x0013 */ Data(Cow<'i, [u8]>),
	/* 0x0016 */ XRelayed(SocketAddr),
	/* 0x0018 */ EvenPort(bool),
	/* 0x0019 */ RequestedTransport(u8),
	/* 0x001A */ DontFragment,
	/* 0x0022 */ ReservationToken(u32),

	// RFC 5245 / 8445:
	/* 0x0024 */ Priority(u32),
	/* 0x0025 */ UseCandidate,
	/* 0x8029 */ IceControlled(u64),
	/* 0x802A */ IceControlling(u64),

	Other(u16, Cow<'i, [u8]>)
}
