use rand_core::RngCore;

#[cfg(target_arch = "wasm32")]
use crate::miniprogram_rng::MiniProgramRng;

#[cfg(not(target_arch = "wasm32"))]
use rand::rngs::OsRng;

pub fn default_rng() -> impl RngCore {
    #[cfg(target_arch = "wasm32")]
    {
        MiniProgramRng
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        OsRng
    }
}
