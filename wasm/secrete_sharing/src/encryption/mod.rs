pub mod crypto_core;

use crypto_core::crypto_interface::LightEciCrypt;
use once_cell::sync::OnceCell;
use crate::{p256_curve, P256_CURVE};

static  P256K1_LECIENCRYPT :OnceCell<LightEciCrypt<'static,4,4>>   = OnceCell::new();    


pub fn p256k1_light_eci_crypt() -> &'static LightEciCrypt<'static, 4, 4> {
  P256K1_LECIENCRYPT.get_or_init(|| {
      // Initialize P256 curve if not already initialized
      let _curve = p256_curve();
      
      // Create new LightEciCrypt instance
      LightEciCrypt::new(P256_CURVE.get().expect("P256 curve should be initialized by p256_curve()"))
  })
}