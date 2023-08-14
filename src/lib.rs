use attr::StunAttrDecodeErr;

pub mod attr;
pub mod attrs;
use attrs::StunAttrs;

#[derive(Debug, Clone)]
pub enum StunDecodeErr {
	PacketTooSmall,
	TypeOutOfRange,
	UnalignedLength,
	BadMagic,
	AttrErr(StunAttrDecodeErr)
}

#[derive(Debug, Clone)]
pub enum StunTyp {
	Req(u16),
	Ind(u16),
	Res(u16),
	Err(u16),
}
impl StunTyp {
	pub fn method(&self) -> u16 {
		match self {
			Self::Req(m) => *m,
			Self::Ind(m) => *m,
			Self::Res(m) => *m,
			Self::Err(m) => *m,
		}
	}
}
impl TryFrom<[u8; 2]> for StunTyp {
	type Error = StunDecodeErr;
	fn try_from(value: [u8; 2]) -> Result<Self, StunDecodeErr> {
		let value = u16::from_be_bytes(value);
		if value >= 0x4000 {
			return Err(StunDecodeErr::TypeOutOfRange);
		}
		let method = ((value & 0b00_00000_0_000_0_1111) >> 0)
			| ((value & 0b00_00000_0_111_0_0000) >> 1)
			| ((value & 0b00_11111_0_000_0_0000) >> 2);
		Ok(match value & 0b00_00000_1_000_1_0000 {
			0b00_000000_0_000_0_0000 => Self::Req(method),
			0b00_000000_0_000_1_0000 => Self::Ind(method),
			0b00_000000_1_000_0_0000 => Self::Res(method),
			0b00_000000_1_000_1_0000 => Self::Err(method),
			_ => unreachable!(),
		})
	}
}
impl From<&StunTyp> for [u8; 2] {
	fn from(value: &StunTyp) -> Self {
		let (class, method) = match value {
			StunTyp::Req(m) => (0b00_000000_0_000_0_0000, m),
			StunTyp::Ind(m) => (0b00_000000_0_000_1_0000, m),
			StunTyp::Res(m) => (0b00_000000_1_000_0_0000, m),
			StunTyp::Err(m) => (0b00_000000_1_000_1_0000, m),
		};
		let ret = ((method & 0b00_00000_0_000_0_1111) << 0)
			| ((method & 0b00_00000_0_111_0_0000) << 1)
			| ((method & 0b00_11111_0_000_0_0000) << 2)
			| class;
		ret.to_be_bytes()
	}
}

pub struct Stun<'i> {
	pub typ: StunTyp,
	pub txid: &'i [u8; 12],
	pub attrs: StunAttrs<'i>,
}
impl<'i> Stun<'i> {
	pub fn len(&self) -> usize {
		20 + self.attrs.length() as usize
	}
	pub fn decode(buff: &'i [u8]) -> Result<Self, StunDecodeErr> {
		if buff.len() < 20 { return Err(StunDecodeErr::PacketTooSmall) }
		let typ = StunTyp::try_from(<[u8; 2]>::try_from(&buff[0..][..2]).unwrap())?;
		
		let length = u16::from_be_bytes((&buff[2..][..2]).try_into().unwrap());
		if length % 4 != 0 { return Err(StunDecodeErr::UnalignedLength) }
		if (20 + length as usize) < buff.len() { return Err(StunDecodeErr::PacketTooSmall) }

		let magic = u32::from_be_bytes((&buff[4..][..4]).try_into().unwrap());
		if magic != 0x2112A442 { return Err(StunDecodeErr::BadMagic) }

		let txid = (&buff[8..][..12]).try_into().unwrap();

		let attrs = StunAttrs::Parse { buff: &buff[20..][..length as usize], header: (&buff[0..][..20]).try_into().unwrap() };
		for res in &attrs {
			if let Err(e) = res {
				return Err(StunDecodeErr::AttrErr(e))
			}
		}

		Ok(Self { typ, txid, attrs })
	}
	pub fn encode(&self, buff: &mut [u8]) {
		buff[0..][..2].copy_from_slice(&<[u8; 2]>::from(&self.typ));
		buff[2..][..2].copy_from_slice(&self.attrs.length().to_be_bytes());
		buff[4..][..4].copy_from_slice(&0x2112A442u32.to_be_bytes());
		buff[8..][..12].copy_from_slice(self.txid);
		let (header, buff) = buff.split_at_mut(20);
		let header = <&[u8; 20]>::try_from(&*header).unwrap();
		self.attrs.encode(buff, header)
	}
}
