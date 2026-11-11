//! Windows' own WebAuthn API (`webauthn.dll`), with the `prf` extension:
//! Windows 11. The credential is made with `hmac-secret` and `credProtect`
//! 3, and the secret asked for with the salt as a `prf` input, which
//! Windows turns into the key's salt exactly as [`crate::prf_salt`] does;
//! so a credential made over HID on Linux opens here and the other way
//! round. Windows asks for the PIN and the touch itself.

use core::ffi::c_void;
use core::ptr::{NonNull, null, null_mut};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Networking::WindowsWebServices::*;
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows_sys::core::{BOOL, HRESULT};
use zeroize::Zeroizing;

use super::wide;
use crate::hid::random;
use crate::{Authenticator, Enrolled, Error};

/// The API version that brought `hmac-secret` salts on assertion.
const PRF_API_VERSION: u32 = WEBAUTHN_API_VERSION_4;
/// How long Windows waits for the PIN and the touch.
const TIMEOUT_MS: u32 = 120_000;

const NTE_USER_CANCELLED: HRESULT = 0x8009_0036_u32 as HRESULT;
const NTE_NOT_FOUND: HRESULT = 0x8009_0011_u32 as HRESULT;
const HRESULT_CANCELLED: HRESULT = 0x8007_04C7_u32 as HRESULT;

/// Whether this Windows can do it: API version 4 or later.
pub fn has_prf() -> bool {
    // SAFETY: takes nothing, returns a number.
    unsafe { WebAuthNGetApiVersionNumber() >= PRF_API_VERSION }
}

/// Windows' own route.
pub struct WebAuthn;

fn window() -> HWND {
    // SAFETY: both only read which window is where.
    unsafe {
        let foreground = GetForegroundWindow();
        if foreground.is_null() {
            GetConsoleWindow()
        } else {
            foreground
        }
    }
}

fn check(hr: HRESULT) -> Result<(), Error> {
    match hr {
        0 => Ok(()),
        NTE_USER_CANCELLED | HRESULT_CANCELLED => Err(Error::Cancelled),
        NTE_NOT_FOUND => Err(Error::NoCredentials),
        hr => {
            // SAFETY: returns a static string Windows owns, or null.
            let name = unsafe { WebAuthNGetErrorName(hr) };
            let name = if name.is_null() {
                String::new()
            } else {
                // SAFETY: a NUL-terminated wide string.
                let len = (0..).take_while(|&i| unsafe { *name.add(i) } != 0).count();
                String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(name, len) })
            };
            Err(Error::Windows(format!("{name} (0x{:08x})", hr as u32)))
        }
    }
}

/// `clientDataJSON` for a ceremony: nothing checks it but the key's
/// signature, which nothing here checks either; a fresh challenge all the
/// same.
fn client_data(kind: &str, rp_id: &str) -> Vec<u8> {
    let mut challenge = [0u8; 32];
    random(&mut challenge);
    let challenge: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        r#"{{"type":"{kind}","challenge":"{challenge}","origin":"https://{rp_id}","crossOrigin":false}}"#
    )
    .into_bytes()
}

impl WebAuthn {
    fn make_credential(&self, rp_id: &str) -> Result<Vec<u8>, Error> {
        let rp_w = wide(rp_id);
        let name_w = wide("Silver Messenger");
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_w.as_ptr(),
            pwszName: name_w.as_ptr(),
            pwszIcon: null(),
        };
        let mut user_id = [0u8; 16];
        random(&mut user_id);
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id.len() as u32,
            pbId: user_id.as_mut_ptr(),
            pwszName: name_w.as_ptr(),
            pwszIcon: null(),
            pwszDisplayName: name_w.as_ptr(),
        };
        let mut param = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut param,
        };
        let mut json = client_data("webauthn.create", rp_id);
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut hmac_secret: BOOL = 1;
        let mut cred_protect = WEBAUTHN_CRED_PROTECT_EXTENSION_IN {
            dwCredProtect: WEBAUTHN_USER_VERIFICATION_REQUIRED,
            bRequireCredProtect: 1,
        };
        let mut extensions = [
            WEBAUTHN_EXTENSION {
                pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
                cbExtension: size_of::<BOOL>() as u32,
                pvExtension: (&raw mut hmac_secret).cast::<c_void>(),
            },
            WEBAUTHN_EXTENSION {
                pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT,
                cbExtension: size_of::<WEBAUTHN_CRED_PROTECT_EXTENSION_IN>() as u32,
                pvExtension: (&raw mut cred_protect).cast::<c_void>(),
            },
        ];
        let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            Extensions: WEBAUTHN_EXTENSIONS {
                cExtensions: extensions.len() as u32,
                pExtensions: extensions.as_mut_ptr(),
            },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            bRequireResidentKey: 0,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            ..Default::default()
        };
        let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = null_mut();
        // SAFETY: every pointer is to a local that outlives the call, and
        // the strings are NUL-terminated; Windows allocates the answer.
        let hr = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                window(),
                &rp,
                &user,
                &params,
                &client,
                &options,
                &mut attestation,
            )
        };
        check(hr)?;
        let Some(attestation) = NonNull::new(attestation) else {
            return Err(Error::Malformed("Windows gave no credential"));
        };
        // SAFETY: Windows' answer, not null, read and then freed once.
        let id = unsafe {
            let a = attestation.as_ref();
            let id = if a.pbCredentialId.is_null() || a.cbCredentialId == 0 {
                None
            } else {
                Some(
                    core::slice::from_raw_parts(a.pbCredentialId, a.cbCredentialId as usize)
                        .to_vec(),
                )
            };
            WebAuthNFreeCredentialAttestation(attestation.as_ptr());
            id
        };
        id.ok_or(Error::Malformed("Windows gave a credential with no id"))
    }

    fn assertion(
        &self,
        rp_id: &str,
        candidates: &[(&[u8], &[u8])],
    ) -> Result<(usize, Zeroizing<[u8; 32]>), Error> {
        if candidates.is_empty() {
            return Err(Error::NoCredentials);
        }
        // Windows takes a prf input of 32 bytes; the salts here are.
        let mut ids: Vec<Vec<u8>> = candidates.iter().map(|(id, _)| id.to_vec()).collect();
        let mut inputs: Vec<[u8; 32]> = candidates
            .iter()
            .map(|(_, input)| {
                <[u8; 32]>::try_from(*input)
                    .map_err(|_| Error::Unsupported("a prf input that is not 32 bytes"))
            })
            .collect::<Result<_, _>>()?;
        let mut creds: Vec<WEBAUTHN_CREDENTIAL_EX> = ids
            .iter_mut()
            .map(|id| WEBAUTHN_CREDENTIAL_EX {
                dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                cbId: id.len() as u32,
                pbId: id.as_mut_ptr(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                dwTransports: 0,
            })
            .collect();
        let mut cred_ptrs: Vec<*mut WEBAUTHN_CREDENTIAL_EX> =
            creds.iter_mut().map(|c| c as *mut _).collect();
        let mut allow = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: cred_ptrs.len() as u32,
            ppCredentials: cred_ptrs.as_mut_ptr(),
        };
        let mut salts: Vec<WEBAUTHN_HMAC_SECRET_SALT> = inputs
            .iter_mut()
            .map(|input| WEBAUTHN_HMAC_SECRET_SALT {
                cbFirst: 32,
                pbFirst: input.as_mut_ptr(),
                cbSecond: 0,
                pbSecond: null_mut(),
            })
            .collect();
        let mut per_cred: Vec<WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT> = ids
            .iter_mut()
            .zip(salts.iter_mut())
            .map(|(id, salt)| WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT {
                cbCredID: id.len() as u32,
                pbCredID: id.as_mut_ptr(),
                pHmacSecretSalt: salt,
            })
            .collect();
        let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: null_mut(),
            cCredWithHmacSecretSaltList: per_cred.len() as u32,
            pCredWithHmacSecretSaltList: per_cred.as_mut_ptr(),
        };
        let mut json = client_data("webauthn.get", rp_id);
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            // No WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG: the salts
            // are prf inputs, which Windows hashes as WebAuthn says.
            dwFlags: 0,
            pAllowCredentialList: &mut allow,
            pHmacSecretSaltValues: &mut salt_values,
            ..Default::default()
        };
        let rp_w = wide(rp_id);
        let mut assertion: *mut WEBAUTHN_ASSERTION = null_mut();
        // SAFETY: as for the credential: locals that outlive the call.
        let hr = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                window(),
                rp_w.as_ptr(),
                &client,
                &options,
                &mut assertion,
            )
        };
        check(hr)?;
        let Some(assertion) = NonNull::new(assertion) else {
            return Err(Error::Malformed("Windows gave no assertion"));
        };
        // SAFETY: Windows' answer, not null, read and then freed once.
        let answer = unsafe {
            let a = assertion.as_ref();
            let id = if a.Credential.pbId.is_null() || a.Credential.cbId == 0 {
                None
            } else {
                Some(
                    core::slice::from_raw_parts(a.Credential.pbId, a.Credential.cbId as usize)
                        .to_vec(),
                )
            };
            let secret = if a.dwVersion >= WEBAUTHN_ASSERTION_VERSION_3
                && !a.pHmacSecret.is_null()
                && (*a.pHmacSecret).cbFirst == 32
                && !(*a.pHmacSecret).pbFirst.is_null()
            {
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(core::slice::from_raw_parts((*a.pHmacSecret).pbFirst, 32));
                Some(out)
            } else {
                None
            };
            WebAuthNFreeAssertion(assertion.as_ptr());
            (id, secret)
        };
        let (id, secret) = answer;
        let secret = secret.ok_or(Error::Unsupported(
            "the prf extension (Windows gave no secret)",
        ))?;
        let index = match id {
            Some(id) => candidates
                .iter()
                .position(|(c, _)| *c == id.as_slice())
                .ok_or(Error::Malformed("an unknown credential answered"))?,
            None if candidates.len() == 1 => 0,
            None => return Err(Error::Malformed("no credential in Windows' answer")),
        };
        Ok((index, secret))
    }
}

impl Authenticator for WebAuthn {
    fn enroll(&mut self, rp_id: &str, input: &[u8]) -> Result<Enrolled, Error> {
        let credential_id = self.make_credential(rp_id)?;
        let (_, secret) = self.assertion(rp_id, &[(&credential_id, input)])?;
        Ok(Enrolled {
            credential_id,
            secret,
        })
    }

    fn secret(
        &mut self,
        rp_id: &str,
        candidates: &[(&[u8], &[u8])],
    ) -> Result<(usize, Zeroizing<[u8; 32]>), Error> {
        self.assertion(rp_id, candidates)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn windows_says_which_api_it_has() {
        // SAFETY: as in `has_prf`.
        let version = unsafe { super::WebAuthNGetApiVersionNumber() };
        assert!(version >= 1, "webauthn.dll answered {version}");
        let _ = super::has_prf();
    }
}
