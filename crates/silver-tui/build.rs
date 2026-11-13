//! Link settings for the Windows binary.

fn main() {
    // Load-time imports (hid.dll, webauthn.dll) resolved from System32
    // only, never from the folder the program sits in, which its user can
    // write to: the same rule `silver_key::harden_dll_search` sets for
    // libraries loaded later. MSVC's linker only; there is no equivalent
    // for the GNU toolchain, whose builds are not released.
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os == "windows" && env == "msvc" {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
