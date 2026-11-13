//! Whether the Windows 10 helper may be started elevated from where the
//! program is (docs/design/security-key.md, section 10).
//!
//! The helper is `silver.exe` itself, started with `runas`. The person
//! approves the UAC prompt expecting this program, so whatever runs must
//! be what was there when they started it: if a program running as them,
//! not elevated, can replace `silver.exe`, put a DLL beside it (Windows
//! looks in the program's own folder first for the DLLs it imports), or
//! swap a folder on its path for another, the prompt they expect hands it
//! administrator rights and the PIN typed into its window. A download
//! kept in the user's own folders is exactly that; one in
//! `C:\Program Files` is not.
//!
//! The Windows code asks `AccessCheck`, for the executable and each
//! folder above it, which rights this user's own token (not elevated) is
//! granted; this decides from those masks, here rather than in the
//! Windows code so that it is tested everywhere.

/// Access rights, as Windows numbers them (winnt.h). On a folder
/// `FILE_WRITE_DATA` is the right to add a file to it and
/// `FILE_APPEND_DATA` the right to add a folder.
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_ADD_FILE: u32 = FILE_WRITE_DATA;
pub const FILE_ADD_SUBDIRECTORY: u32 = FILE_APPEND_DATA;
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
pub const DELETE: u32 = 0x0001_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;

/// Rights that let their holder give themselves any other: whoever may
/// rewrite an object's access list or take it over may then do anything.
const TAKE_OVER: u32 = WRITE_DAC | WRITE_OWNER;

/// Why the executable at `file`, with the folders above it `folders`
/// (its own first, the drive's root last), could be changed by whoever
/// holds the rights each mask grants; `None` when it could not.
///
/// * The executable itself: written to, or taken over.
/// * Its own folder: a file added (a DLL it imports, or a new
///   `silver.exe` once the old is moved aside), a folder added, or the
///   folder taken over.
/// * Any folder above: taken over; or the folder on the path below it
///   moved away (the right to delete it, or to delete what is in this
///   one) and another made in its place (the right to add a folder here).
///   A drive's root lets anyone add a folder, which is harmless while
///   nobody may delete or rename what is already in it.
pub fn exposed(file: u32, folders: &[u32]) -> Option<&'static str> {
    if file & (FILE_WRITE_DATA | FILE_APPEND_DATA | TAKE_OVER) != 0 {
        return Some("a program running as you can change silver.exe itself");
    }
    let Some(&own) = folders.first() else {
        return Some("it is in no folder");
    };
    if own & (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | TAKE_OVER) != 0 {
        return Some(
            "a program running as you can add files to its folder, such as a DLL it loads or \
             another silver.exe",
        );
    }
    for pair in folders.windows(2) {
        let (below, above) = (pair[0], pair[1]);
        if above & TAKE_OVER != 0 {
            return Some(
                "a program running as you can change the permissions of a folder above it",
            );
        }
        let movable = below & DELETE != 0 || above & FILE_DELETE_CHILD != 0;
        if movable && above & FILE_ADD_SUBDIRECTORY != 0 {
            return Some(
                "a program running as you can move a folder above it aside and put another in its \
                 place",
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a user is granted under the default access lists: read and
    /// run (0x1200a9) on the executable and on `C:\Program Files` and the
    /// folders under it; add a folder (and read) on the drive's root.
    const READ: u32 = 0x0012_00a9;
    const ROOT: u32 = READ | FILE_ADD_SUBDIRECTORY;
    /// Full control (0x1f01ff), as on anything under the user's profile.
    const FULL: u32 = 0x001f_01ff;

    #[test]
    fn program_files_is_safe() {
        // C:\Program Files\Silver Messenger\silver.exe
        assert_eq!(exposed(READ, &[READ, READ, ROOT]), None);
    }

    #[test]
    fn a_folder_of_the_users_own_is_not() {
        // C:\Users\me\Downloads\silver.exe
        assert!(exposed(FULL, &[FULL, FULL, READ, ROOT]).is_some());
        // The executable read-only, its folder not.
        assert!(exposed(READ, &[FULL, FULL, READ, ROOT]).is_some());
        // A folder the user made at the root (C:\Tools\silver.exe): the
        // maker owns it.
        assert!(exposed(READ, &[READ | WRITE_DAC, ROOT]).is_some());
    }

    #[test]
    fn each_way_to_change_it_is_seen() {
        for file in [FILE_WRITE_DATA, FILE_APPEND_DATA, WRITE_DAC, WRITE_OWNER] {
            assert!(exposed(READ | file, &[READ, ROOT]).is_some(), "{file:x}");
        }
        for own in [FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, WRITE_DAC, WRITE_OWNER] {
            assert!(exposed(READ, &[READ | own, ROOT]).is_some(), "{own:x}");
        }
        // A folder above that can be taken over.
        assert!(exposed(READ, &[READ, READ | WRITE_OWNER, ROOT]).is_some());
        // The executable's folder can be deleted, and one made in its
        // place; or the parent lets its children be deleted.
        assert!(exposed(READ, &[READ | DELETE, ROOT]).is_some());
        assert!(exposed(READ, &[READ, ROOT | FILE_DELETE_CHILD]).is_some());
        // Higher up the same.
        assert!(exposed(READ, &[READ, READ | DELETE, ROOT]).is_some());
        // Deleting alone, or adding alone, replaces nothing.
        assert_eq!(exposed(READ | DELETE, &[READ, READ, ROOT]), None);
        assert_eq!(exposed(READ, &[READ, READ | DELETE, READ]), None);
        assert_eq!(exposed(READ, &[READ, READ | FILE_DELETE_CHILD]), None);
    }

    #[test]
    fn nowhere_is_not_safe() {
        assert!(exposed(READ, &[]).is_some());
    }
}
