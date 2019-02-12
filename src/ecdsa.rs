use std::io::{Write};
use byteorder::{BigEndian, WriteBytesExt};
use eagre_asn1::der::DER;

#[derive(Debug)]
pub struct ECDSASign {
	pub r: Vec<u8>,
	pub s: Vec<u8>,
}

der_sequence!{
	ECDSASign:
		r: NOTAG TYPE Vec<u8>,
		s: NOTAG TYPE Vec<u8>,
}

pub static CURVE_INDETIFIER: &'static str = "nistp256";
pub static CURVE_TYPE: &'static str = "ecdsa-sha2-nistp256";

pub struct EcdsaSha2Nistp256;
impl EcdsaSha2Nistp256 {

	// write to SSH-Key Format
	pub fn write(key: Vec<u8>) -> Vec<u8> {
		let curvetype = String::from(CURVE_TYPE);
		let identifier = String::from(CURVE_INDETIFIER);
		let mut data = vec![];
		//write curve type
		data.write_u32::<BigEndian>(curvetype.len() as u32).unwrap();
		data.write_all(curvetype.as_bytes());
		//write identifier
		data.write_u32::<BigEndian>(identifier.len() as u32).unwrap();
		data.write_all(identifier.as_bytes());
		//write key
		data.write_u32::<BigEndian>(key.len() as u32).unwrap();
		data.write_all(key.as_slice());
		data 
	}

	pub fn parse_asn1(signed_data: Vec<u8>) -> ECDSASign{
		ECDSASign::der_from_bytes(signed_data).unwrap()
	}
}