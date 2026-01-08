/// MiniProgramRng
///
/// <p>基于 JavaScript Math.random 的随机数实现，仅用于
/// WebAssembly / 小程序环境的兼容性支持，不满足密码学安全要求</p>
use rand_core::{RngCore, Error};
use js_sys::Math;

pub struct MiniProgramRng;

impl RngCore for MiniProgramRng {
    fn next_u32(&mut self) -> u32 {
        (Math::random() * u32::MAX as f64) as u32
    }

    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | self.next_u32() as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = (Math::random() * 256.0) as u8;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
