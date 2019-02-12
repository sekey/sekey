use ssh_agent::Response;
use ssh_agent::Identity;
use ssh_agent::SSHAgentHandler;

use std::io::{Write};
use byteorder::{BigEndian, WriteBytesExt};

use crypto::digest::Digest;
use crypto::sha1::Sha1;

use crate::Keychain;
use crate::ecdsa::{EcdsaSha2Nistp256, CURVE_TYPE};

use ssh_agent::error::HandleResult;


pub struct Handler;
impl SSHAgentHandler for Handler {
	fn new() -> Self {
		Self {}
	}

	fn identities(&mut self) -> HandleResult<Response> {
		// list identities and return
		let keys = Keychain::get_public_keys();
		let mut idents = Vec::new();
		for key in keys {
			idents.push(Identity{
				key_blob: EcdsaSha2Nistp256::write(key.key),
				key_comment: String::from(CURVE_TYPE)
			});
		}
		Ok(Response::Identities(idents))

	}

	fn sign_request(&mut self, pubkey: Vec<u8>, data: Vec<u8>, _flags: u32) -> HandleResult<Response> {
		
		// parse the pubkey that server send to us, then hash it and we will use that
		// hash to get the key from the enclave to sign
		let pubkey = EcdsaSha2Nistp256::read(pubkey);
		let mut hasher = Sha1::new();

		let mut hash: [u8; 20] = [0; 20];
		hasher.input(pubkey.as_slice());
		hasher.result(&mut hash);


		// here we sign the request and do all the enclave communication
		let signed = Keychain::sign_data(data, hash.to_vec())?;
		let ecdsasign = EcdsaSha2Nistp256::parse_asn1(signed);

		//sign that we would return
		let mut signature:Vec<u8> = Vec::new();

		//write signR
		signature.write_u32::<BigEndian>(ecdsasign.r.len() as u32).unwrap();
		signature.write_all(ecdsasign.r.as_slice())?;
		
		//write signS
		signature.write_u32::<BigEndian>(ecdsasign.s.len() as u32).unwrap();
		signature.write_all(ecdsasign.s.as_slice())?;

		// response signature
		Ok(Response::SignResponse {
			algo_name: String::from(CURVE_TYPE),
			signature: signature
		})
	}


}