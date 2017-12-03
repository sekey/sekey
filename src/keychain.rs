
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::boolean::CFBoolean;
use core_foundation::array::{CFArray, CFArrayRef, FromVoid};
use core_foundation::base::{TCFType, CFType, CFTypeRef, OSStatus};
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::base::{ kCFAllocatorDefault, CFAllocatorRef};

use std::ptr;

pub static PRIVATE_KEY_NAME: &'static str = "com.sekey.priv";
pub static PUBLIC_KEY_NAME: &'static str = "com.sekey.pub";

static ERR_SEC_DUPLICATE_ITEM: OSStatus = -25299;
static ERR_SEC_SUCCESS: OSStatus = 0;

type SecAccessControlCreateFlags = u32;
static K_SEC_ACCESS_CONTROL_TOUCH_ID_ANY: u32 = 1 << 1;
static K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE: u32 = 1 << 30;


extern "C" {
    static kSecValueRef: CFStringRef;
    static kSecValueData: CFStringRef;
    static kSecClass: CFStringRef;
    static kSecClassKey: CFStringRef;
    static kSecAttrKeyType: CFStringRef;
    static kSecAttrKeyTypeEC: CFStringRef;
    static kSecAttrApplicationTag: CFStringRef;
    static kSecAttrKeyClass: CFStringRef;
    static kSecAttrKeyClassPublic: CFStringRef;
    static kSecAttrKeyClassPrivate: CFStringRef;
    static kSecReturnRef: CFStringRef;
    static kSecMatchLimit: CFStringRef;
    static kSecMatchLimitAll: CFStringRef;
    static kSecReturnAttributes: CFStringRef;
    static kSecAttrIsPermanent: CFStringRef;
    static kSecAttrAccessControl: CFStringRef;
    static kSecAttrLabel: CFStringRef;
    static kSecAttrApplicationLabel: CFStringRef;
    static kSecUseOperationPrompt: CFStringRef;
    static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: CFStringRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
    static kSecAttrTokenID: CFStringRef;
    static kSecAttrTokenIDSecureEnclave: CFStringRef;
    static kSecPrivateKeyAttrs: CFStringRef;
    static kSecReturnData: CFStringRef;

    fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecAccessControlCreateWithFlags(allocator: CFAllocatorRef, protection: CFTypeRef, flags: SecAccessControlCreateFlags, error: *mut CFTypeRef) -> CFTypeRef;
    fn SecKeyCreateSignature(key: CFTypeRef, algorithm: CFStringRef, dataToSign: CFDataRef, error: *mut CFTypeRef) -> CFDataRef;
    fn SecKeyCopyAttributes(key: CFTypeRef) -> CFDictionaryRef;
    fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
    fn SecKeyGeneratePair(parameters: CFDictionaryRef, publicKey: *mut CFTypeRef, privateKey: *mut CFTypeRef)-> OSStatus;
    fn SecItemAdd(query: CFDictionaryRef, keyBits: *mut CFTypeRef) -> OSStatus;
}

pub struct CFDict{
    params: Vec<(CFString, CFType)>,
}

impl CFDict {
    pub fn new() -> Self {
        Self {
            params: vec![]
        }
    }
    pub fn add_string_ref(mut self, key: CFStringRef, value:CFStringRef) -> Self {
        unsafe {
            self.params.push((
                CFString::wrap_under_get_rule(key),
                CFType::wrap_under_get_rule(value as *const _)
            ));
        }
        self
    }

    pub fn add_label(mut self, key: CFStringRef, label: &str) -> Self {
        unsafe {
            self.params.push((
                CFString::wrap_under_get_rule(key),
                CFString::new(label).as_CFType()
            ));
        }
        self
    }

    pub fn add_cfdata(mut self, key: CFStringRef, label: CFData) -> Self {
        unsafe {
            self.params.push((
                CFString::wrap_under_get_rule(key),
                label.as_CFType()
            ));
        }
        self
    }

    pub fn add_cfdict(mut self, key: CFStringRef, dict: CFDictionary) -> Self {
        unsafe {
            self.params.push((
                CFString::wrap_under_get_rule(key),
                dict.as_CFType()
            ));
        }
        self
    }
    pub fn add_cftyperef(mut self, key: CFStringRef, reference: CFTypeRef) -> Self {
        unsafe {
            self.params.push((
                CFString::wrap_under_get_rule(key),
                TCFType::wrap_under_get_rule(reference)
            ));
        }
        self
    }
    pub fn add_boolean(mut self, key: CFStringRef, boolean: bool) -> Self {
        unsafe {
            let boolean = match boolean {
                true => CFBoolean::true_value().as_CFType(),
                false => CFBoolean::false_value().as_CFType()
            };

            self.params.push((
                CFString::wrap_under_get_rule(key),
                boolean
            ));
        }
        self
    }

    pub fn get(&self) -> CFDictionary {
        CFDictionary::from_CFType_pairs(&self.params)
    }
}


#[derive(Debug)]
pub struct PubKey {
    pub label: String,
    pub hash: Vec<u8>,
    pub key: Vec<u8>,
}

pub struct Keychain;

impl Keychain {

    pub unsafe fn sec_item_copy_matching(dict: CFDictionary) -> Vec<CFDictionary>{
            let mut items = vec![];

            let mut ret:CFTypeRef = ptr::null();
            SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut ret);

            if ret.is_null(){
                return items;
            }

            let data = CFType::from_void(ret);
            if data.instance_of::<_, CFArray>(){
                let array:CFArray = CFArray::wrap_under_create_rule(ret as CFArrayRef);
                for item in &array {
                    let obj = CFType::from_void(item);
                    if obj.instance_of::<_, CFDictionary>(){
                        let dict = CFDictionary::wrap_under_get_rule(item as CFDictionaryRef);
                        items.push(dict);
                    }
                }

            }else {
                items.push(CFDictionary::wrap_under_get_rule(ret as CFDictionaryRef));
            }

            items       
    }

    fn get_pubkey_from_cfdictionary(key: CFDictionary) -> PubKey {
        let label;
        let key_id;
        let key_data;
        unsafe {
            label = key.find(kSecAttrLabel as *const _)
                        .map(|label| {
                                CFString::wrap_under_get_rule(label as *const _).to_string()
                        }).unwrap_or_else(|| String::new());

            key_id = key.find(kSecAttrApplicationLabel as *const _)
                            .map(|key_id| {
                                CFData::wrap_under_get_rule(key_id as *const _).to_vec()
                            }).unwrap_or_else(|| Vec::new());
            
            // get the public key Vec<u8>, first we have to get the reference
            // and then the data from the dict object
            key_data = key.find(kSecValueRef as *const _)
                        .map(|key_ref| {
                                CFDictionary::wrap_under_get_rule(SecKeyCopyAttributes(key_ref) as CFDictionaryRef)
                                .find(kSecValueData as *const _)
                                .map(|keydata|{
                                    CFData::wrap_under_get_rule(keydata as *const _).to_vec()
                                })
                                .unwrap_or_else(|| Vec::new())
                        }).unwrap();
        }
        PubKey { label: label, hash: key_id, key: key_data }
    }

    pub fn get_public_keys() -> Vec<PubKey> {
        let mut pub_keys = Vec::new();
        unsafe {
            // create the query to ask the keychaing.
            let dict  = CFDict::new()
                .add_string_ref(kSecClass, kSecClassKey)
                .add_string_ref(kSecAttrKeyType, kSecAttrKeyTypeEC)
                .add_label(kSecAttrApplicationTag, PUBLIC_KEY_NAME)
                .add_string_ref(kSecAttrKeyClass, kSecAttrKeyClassPublic)
                .add_boolean(kSecReturnRef, true)
                .add_string_ref(kSecMatchLimit, kSecMatchLimitAll)
                .add_boolean(kSecReturnAttributes, true)
                .get();

            let keys = Keychain::sec_item_copy_matching(dict);
            // iter thru the keys and the get information from the key dict.
            for key in keys {
                pub_keys.push(Keychain::get_pubkey_from_cfdictionary(key));
            }

        }
        pub_keys
    }

    unsafe fn get_public_ref(hash:Vec<u8>)-> Result<CFTypeRef, &'static str>{
        let data = CFData::from_buffer(hash.as_slice());
        let dict  = CFDict::new()
                .add_string_ref(kSecClass, kSecClassKey)
                .add_string_ref(kSecAttrKeyType, kSecAttrKeyTypeEC)
                .add_label(kSecAttrApplicationTag, PUBLIC_KEY_NAME)
                .add_cfdata(kSecAttrApplicationLabel, data)
                .add_string_ref(kSecAttrKeyClass, kSecAttrKeyClassPublic)
                .add_boolean(kSecReturnRef, true)
                .add_boolean(kSecReturnAttributes, true)
                .get();
        let mut keys = Keychain::sec_item_copy_matching(dict);
        if let Some(key_) = keys.pop(){
             Ok(key_.as_CFTypeRef())
        } else {
            Err("Key not found")
        }
    }

    pub fn get_public_key(hash:Vec<u8>) -> Result<PubKey, &'static str> {
        let key:PubKey;
        unsafe {
            let keyref = Keychain::get_public_ref(hash)?;
            let keyref = CFDictionary::wrap_under_get_rule(keyref as CFDictionaryRef);
            key = Keychain::get_pubkey_from_cfdictionary(keyref);
        }

        Ok(key)
    }

    unsafe fn get_private_ref(hash:Vec<u8>)-> Result<CFTypeRef, &'static str>{
        let data = CFData::from_buffer(hash.as_slice());
        let dict  = CFDict::new()
            .add_string_ref(kSecClass, kSecClassKey)
            .add_label(kSecAttrLabel, PRIVATE_KEY_NAME)
            .add_string_ref(kSecAttrKeyClass, kSecAttrKeyClassPrivate)
            .add_cfdata(kSecAttrApplicationLabel, data)
            .add_boolean(kSecReturnRef, true)
            .add_label(kSecUseOperationPrompt, "Authenticate to Sign Data")
            .get();

            let mut keys = Keychain::sec_item_copy_matching(dict);

            if let Some(key_) = keys.pop(){
                 Ok(key_.as_CFTypeRef())
            } else {
                Err("Key not found")
            }

    }

    pub fn sign_data(data: Vec<u8>, key_hash: Vec<u8>) -> Result<Vec<u8>, &'static str> {
        let retdata: Vec<u8>;
        unsafe {
            let data = CFData::from_buffer(data.as_slice());
            let keyref = Keychain::get_private_ref(key_hash)?;
            let mut err = ptr::null();
            let data = SecKeyCreateSignature(keyref, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, data.as_concrete_TypeRef(), &mut err);
            
            if !err.is_null(){
                return Err("Error trying to sign data");
            }
            retdata = CFData::wrap_under_get_rule(data as *const _).to_vec()
        }
        Ok(retdata)
    }

    unsafe fn delete_private_key(hash:Vec<u8>){
        let data = CFData::from_buffer(hash.as_slice());
        let dict  = CFDict::new()
            .add_string_ref(kSecClass, kSecClassKey)
            .add_label(kSecAttrLabel, PRIVATE_KEY_NAME)
            .add_string_ref(kSecAttrKeyClass, kSecAttrKeyClassPrivate)
            .add_cfdata(kSecAttrApplicationLabel, data)
            .add_boolean(kSecReturnRef, true)
            .get();

        let mut err = SecItemDelete(dict.as_concrete_TypeRef());
        while err == ERR_SEC_DUPLICATE_ITEM {
            err = SecItemDelete(dict.as_concrete_TypeRef());
        }

    }

    unsafe fn delete_public_key(hash:Vec<u8>){
        let data = CFData::from_buffer(hash.as_slice());
        let dict  = CFDict::new()
            .add_string_ref(kSecClass, kSecClassKey)
            .add_string_ref(kSecAttrKeyType, kSecAttrKeyTypeEC)
            .add_label(kSecAttrApplicationTag, PUBLIC_KEY_NAME)
            .add_cfdata(kSecAttrApplicationLabel, data)
            .add_string_ref(kSecAttrKeyClass, kSecAttrKeyClassPublic)
            .add_boolean(kSecReturnRef, true)
            .get();

        let mut err = SecItemDelete(dict.as_concrete_TypeRef());
        while err == ERR_SEC_DUPLICATE_ITEM {
            err = SecItemDelete(dict.as_concrete_TypeRef());
        }
    }

    pub fn delete_keypair(hash:Vec<u8>) -> Result<(), &'static str> {
        unsafe {
            Keychain::delete_private_key(hash.clone());
            Keychain::delete_public_key(hash);
        }
        Ok(())
    }

    unsafe fn save_public_key(key: CFTypeRef, label: String) {
        let save_key_dict  = CFDict::new()
            .add_string_ref(kSecClass, kSecClassKey)
            .add_string_ref(kSecAttrKeyType, kSecAttrKeyTypeEC)
            .add_string_ref(kSecAttrKeyClass, kSecAttrKeyClassPublic)
            .add_label(kSecAttrApplicationTag, PUBLIC_KEY_NAME)
            .add_cftyperef(kSecValueRef, key)
            .add_boolean(kSecAttrIsPermanent, true)
            .add_boolean(kSecReturnData, true)
            .add_label(kSecAttrLabel, label.as_str())
            .get();


            let mut key_bits:CFTypeRef = ptr::null();

            let mut err = SecItemAdd(save_key_dict.as_concrete_TypeRef(), &mut key_bits); 
            while err == ERR_SEC_DUPLICATE_ITEM {
                err = SecItemDelete(save_key_dict.as_concrete_TypeRef());  
            }
            SecItemAdd(save_key_dict.as_concrete_TypeRef(), &mut key_bits); 
    }

    pub fn generate_keypair(label: String) -> Result<(), &'static str>{
        unsafe {
            let mut error:CFTypeRef = ptr::null();

            let access_control = SecAccessControlCreateWithFlags(
                                    kCFAllocatorDefault,
                                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly as *const _,
                                    K_SEC_ACCESS_CONTROL_TOUCH_ID_ANY | K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE,
                                    &mut error
                                );

            if !error.is_null(){
                return Err("Error creating Access Control Flags");
            }
            
            let access_control_dict  = CFDict::new()
                .add_label(kSecAttrLabel, PRIVATE_KEY_NAME)
                .add_boolean(kSecAttrIsPermanent, true)
                .add_cftyperef(kSecAttrAccessControl, access_control)
                .get();

            let gen_pair_dict  = CFDict::new()
                .add_label(kSecAttrLabel, PRIVATE_KEY_NAME)
                .add_string_ref(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
                .add_string_ref(kSecAttrKeyType, kSecAttrKeyTypeEC)
                .add_cfdict(kSecPrivateKeyAttrs, access_control_dict)
                .get();

            let mut public_key_ref:CFTypeRef = ptr::null();
            let mut private_key_ref:CFTypeRef = ptr::null();

            let status = SecKeyGeneratePair(gen_pair_dict.as_concrete_TypeRef(),
                &mut public_key_ref,
                &mut private_key_ref);

            if status != ERR_SEC_SUCCESS {
                return Err("Error creating keypair")
            }
            Keychain::save_public_key(public_key_ref, label);
            
        }
        Ok(())

    }

}