use std::io::{Write};
use byteorder::{BigEndian, WriteBytesExt};

use crypto::digest::Digest;
use crypto::sha1::Sha1;

use crate::Keychain;
use crate::ecdsa::{EcdsaSha2Nistp256};

use std::error::Error;

use ssh_agent::proto::{from_bytes, to_bytes};
use ssh_agent::proto::message::{self, Message, SignRequest};
use ssh_agent::proto::signature::{self, Signature};
use ssh_agent::proto::public_key::{PublicKey, EcDsaPublicKey};
use ssh_agent::agent::Agent;


#[derive(Clone, PartialEq, Debug)]
struct Identity {
    pubkey: PublicKey,
    comment: String
}

#[derive(Clone, PartialEq, Debug)]
pub struct SeKeyAgent {}

impl SeKeyAgent {
    pub fn new() -> Self {
        Self { 

		}
    }

     
	fn identities(&self) -> Vec<Identity>{
		let mut identities = vec![];
		let keys = Keychain::get_public_keys();
		
		for key in keys {
			let pubkey = EcDsaPublicKey {
				identifier: "nistp256".to_string(), 
				q: key.key
			};

			identities.push(Identity {
				pubkey: PublicKey::EcDsa(pubkey),
				comment: key.label 
			});
		}
		
		identities
	}

    fn sign(&self, sign_request: &SignRequest) -> Result<Signature, Box<Error>> {
        let pubkey: PublicKey = from_bytes(&sign_request.pubkey_blob)?;
		
		match pubkey {
			PublicKey::EcDsa(ref key) => {

				let mut hasher = Sha1::new();

				let mut hash: [u8; 20] = [0; 20];
				hasher.input(&key.q);
				hasher.result(&mut hash);
				
				//here we sign the request and do all the enclave communication
				let signed = Keychain::sign_data(sign_request.data.to_vec(), hash.to_vec())?;
				let ecdsasign = EcdsaSha2Nistp256::parse_asn1(signed);

				//sign that we would return
				let mut signature:Vec<u8> = Vec::new();

				//write signR
				signature.write_u32::<BigEndian>(ecdsasign.r.len() as u32).unwrap();
				signature.write_all(ecdsasign.r.as_slice())?;
				
				//write signS
				signature.write_u32::<BigEndian>(ecdsasign.s.len() as u32).unwrap();
				signature.write_all(ecdsasign.s.as_slice())?;

				Ok(Signature {
			        algorithm: "ecdsa-sha2-nistp256".to_string(),
			        blob: signature
			    })
			}
			_ => Err(From::from("Signature for key type not implemented"))
		}

    }
    
    fn handle_message(&self, request: Message) -> Result<Message, Box<Error>>  {
        info!("Request: {:?}", request);
        let response = match request {
            Message::RequestIdentities => {
                let mut identities = vec![];
                for identity in self.identities() {
                    identities.push(message::Identity {
                        pubkey_blob: to_bytes(&identity.pubkey)?,
                        comment: identity.comment.clone()
                    })
                }
                Ok(Message::IdentitiesAnswer(identities))
            },
            Message::SignRequest(request) => {
                let signature = to_bytes(&self.sign(&request)?)?;
                Ok(Message::SignResponse(signature))
            },
            _ => Err(From::from(format!("Unknown message: {:?}", request)))
        };
        info!("Response {:?}", response);
        return response;
    }
}


impl Agent for SeKeyAgent {
    type Error = ();
    
    fn handle(&self, message: Message) -> Result<Message, ()> {
        self.handle_message(message).or_else(|error| {
            println!("Error handling message - {:?}", error);
            Ok(Message::Failure)
        })
    }
}

pub fn run_agent(path: &str) {
	let agent = SeKeyAgent::new();
	let _ = agent.run_unix(path);
}