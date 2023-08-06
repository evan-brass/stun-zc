use std::borrow::Cow;
use eyre::Result;

pub mod attr;
pub mod auth;
use attr::StunAttrs;
use auth::StunAuth;

pub enum StunTyp {
	Req(u16),
	Ind(u16),
	Res(u16),
	Err(u16)
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
