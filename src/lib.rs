use std::borrow::Cow;
use eyre::Result;

pub mod attr;
pub mod auth;
use attr::StunAttrs;
use auth::StunAuth;

#[derive(Debug, Clone)]
pub enum StunTyp {
	Req(u16),
	Ind(u16),
	Res(u16),
	Err(u16)
}
impl StunTyp {
	pub fn method(&self) -> u16 {
		match self {
			Self::Req(m) => *m,
			Self::Ind(m) => *m,
			Self::Res(m) => *m,
			Self::Err(m) => *m
		}
	}
}
impl TryFrom<u16> for StunTyp {
	type Error = eyre::Report;
	fn try_from(value: u16) -> Result<Self> {
		if value >= 0x4000 { return Err(eyre!("Invalid STUN type {value}.")); }
		let method = 
			((value & 0b00_00000_0_000_0_1111) >> 0) |
			((value & 0b00_00000_0_111_0_0000) >> 1) |
			((value & 0b00_11111_0_000_0_0000) >> 2);
		Ok(match value & 0b00_00000_1_000_1_0000 {
			0b00_000000_0_000_0_0000 => Self::Req(method),
			0b00_000000_0_000_1_0000 => Self::Ind(method),
			0b00_000000_1_000_0_0000 => Self::Res(method),
			0b00_000000_1_000_1_0000 => Self::Err(method),
			_ => unreachable!()
		})
	}
}
impl From<&StunTyp> for u16 {
	fn from(value: &StunTyp) -> Self {
		let (class, method) = match value {
			StunTyp::Req(m) => (0b00_000000_0_000_0_0000, m),
			StunTyp::Ind(m) => (0b00_000000_0_000_1_0000, m),
			StunTyp::Res(m) => (0b00_000000_1_000_0_0000, m),
			StunTyp::Err(m) => (0b00_000000_1_000_1_0000, m),
		};
		((method & 0b00_00000_0_000_0_1111) << 0) |
		((method & 0b00_00000_0_111_0_0000) << 1) |
		((method & 0b00_11111_0_000_0_0000) << 2) |
		class
	}
}

pub struct Stun<'i> {
	pub typ: StunTyp,
	pub txid: Cow<'i, [u8; 12]>,
	pub attrs: StunAttrs<'i>
}
impl<'i> Stun<'i> {
	pub fn decode(_buff: &'i [u8], _auth: StunAuth<'_>) -> Result<Self> {
		todo!();
	}
	pub fn encode(&self, _buff: &mut [u8], _auth: StunAuth<'_>) -> Result<usize> {
		todo!();
	}
}
