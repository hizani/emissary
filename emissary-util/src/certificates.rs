// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use rsa::{BigUint, RsaPublicKey};
use x509_parser::public_key::PublicKey;

use std::{collections::HashMap, sync::LazyLock};

const ACETONE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/acetone_at_mail.i2p.crt"
));
const CREATIVECOWPAT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/creativecowpat_at_mail.i2p.crt"
));
const HOTTUNA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/hottuna_at_mail.i2p.crt"
));
const LAZYGRAVY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/lazygravy_at_mail.i2p.crt"
));
const RAMBLER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/rambler_at_mail.i2p.crt"
));
const ADMIN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/admin_at_stormycloud.org.crt"
));
const ECHELON3: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/echelon3_at_mail.i2p.crt"
));
const I2P_RESEED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/i2p-reseed_at_mk16.de.crt"
));
const ORIGNAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/orignal_at_mail.i2p.crt"
));
const RESEED_DIVA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/reseed_at_diva.exchange.crt"
));
const ARNAVBHATT288: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/arnavbhatt288_at_mail.i2p.crt"
));
const HANKHILL19580: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/hankhill19580_at_gmail.com.crt"
));
const IGOR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/igor_at_novg.net.crt"
));
const R4SAS_RESEED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/certificates/r4sas-reseed_at_mail.i2p.crt"
));

/// Certificates of the reseed bundle signers.
pub const CERTIFICATES: &[(&str, &str); 14] = &[
    ("acetone@mail.i2p.crt", ACETONE),
    ("creativecowpat@mail.i2p.crt", CREATIVECOWPAT),
    ("hottuna@mail.i2p.crt", HOTTUNA),
    ("lazygravy@mail.i2p.crt", LAZYGRAVY),
    ("rambler@mail.i2p.crt", RAMBLER),
    ("admin@stormycloud.org.crt", ADMIN),
    ("echelon3@mail.i2p.crt", ECHELON3),
    ("i2p-reseed@mk16.de.crt", I2P_RESEED),
    ("orignal@mail.i2p.crt", ORIGNAL),
    ("reseed@diva.exchange.crt", RESEED_DIVA),
    ("arnavbhatt288@mail.i2p.crt", ARNAVBHATT288),
    ("hankhill19580@gmail.com.crt", HANKHILL19580),
    ("igor@novg.net.crt", IGOR),
    ("r4sas-reseed@mail.i2p.crt", R4SAS_RESEED),
];

/// Public keys of the reseed bundle signers.
pub static PUBLIC_KEYS: LazyLock<HashMap<&'static str, RsaPublicKey>> = LazyLock::new(|| {
    CERTIFICATES
        .iter()
        .filter_map(|(key, value)| {
            let cert = pem::parse(value).ok()?.into_contents();
            let (_, cert) = x509_parser::parse_x509_certificate(&cert).ok()?;

            match cert.public_key().parsed().unwrap() {
                PublicKey::RSA(public_key) => {
                    let modulus = BigUint::from_bytes_be(public_key.modulus);
                    let exponent = BigUint::from_bytes_be(public_key.exponent);

                    Some((*key, RsaPublicKey::new(modulus, exponent).ok()?))
                }
                _ => None,
            }
        })
        .collect()
});
