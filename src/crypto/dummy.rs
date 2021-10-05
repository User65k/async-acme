fn print_err()
{
    println!("no crypto backend selected");
    eprintln!("no crypto backend selected");
}

#[derive(Debug)]
pub struct EcdsaP256SHA256KeyPair();

impl EcdsaP256SHA256KeyPair {
    pub fn load(_pkcs8: &[u8]) -> Result<EcdsaP256SHA256KeyPair, ()> {
        print_err();
        Err(())
    }
    pub fn generate() -> Result<impl AsRef<[u8]>, ()> {
        print_err();
        std::result::Result::<&[u8], ()>::Err(())
    }
    pub fn sign(&self, message: &[u8],
    ) -> Result<impl AsRef<[u8]>, ()> {
        std::result::Result::<&[u8], ()>::Err(())
    }
    pub fn public_key(&self) -> &'static [u8] {
        &[]
    }
}

pub fn sha256(_a: &[u8]) -> &'static [u8] {
    print_err();
    &[]
}
pub struct DummyHash{}
pub fn sha256_hasher() -> DummyHash {
    print_err();
    DummyHash{}
}
impl DummyHash {
    pub fn update(&mut self, _a: &[u8])
    {}
    pub fn finish(self) -> &'static [u8]
    {
        &[]
    }
}

pub struct Identity{}
pub fn gen_acme_cert(_domains: Vec<String>, _acme_hash: &[u8]) -> Result<Identity, ()> {
    print_err();
    Err(())
}

pub struct CertBuilder {
}
impl CertBuilder {
    pub fn gen_new(domains: Vec<String>) -> Result<CertBuilder, ()> {
        print_err();
        Err(())
    }
    pub fn get_csr(&self) -> Result<Vec<u8>,()> {
        Err(())
    }
    pub fn private_key_as_pem_pkcs8(&self) -> String {
        "".to_string()
    }
    pub fn sign(self, mut pem_cert: &[u8]) -> Result<Identity, ()> {
        Err(())
    }
}
