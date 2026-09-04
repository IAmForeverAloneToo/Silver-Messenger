//! QR codes drawn with half-block characters, two modules per row.

use qrcode::{Color, EcLevel, QrCode};

/// Light modules around the code, as the QR standard asks for.
const QUIET_ZONE: i32 = 2;

/// `text` as rows of `█ ▀ ▄` and spaces, meant to be shown as dark text on
/// a light background. Each row covers two module rows.
pub fn render(text: &str) -> Result<Vec<String>, String> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L)
        .map_err(|e| e.to_string())?;
    let width = code.width() as i32;
    let modules = code.to_colors();
    let dark = |x: i32, y: i32| -> bool {
        (0..width).contains(&x)
            && (0..width).contains(&y)
            && modules[(y * width + x) as usize] == Color::Dark
    };
    let mut rows = Vec::new();
    let mut y = -QUIET_ZONE;
    while y < width + QUIET_ZONE {
        let row: String = (-QUIET_ZONE..width + QUIET_ZONE)
            .map(|x| match (dark(x, y), dark(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            })
            .collect();
        rows.push(row);
        y += 2;
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_square_with_a_quiet_zone() {
        let rows = render("silver://add/test").unwrap();
        let width = rows[0].chars().count();
        assert!(rows.iter().all(|r| r.chars().count() == width));
        // Quiet zone: the first row is blank, and every row starts and
        // ends with two blanks.
        assert!(rows[0].trim().is_empty());
        assert!(
            rows.iter()
                .all(|r| r.starts_with("  ") && r.ends_with("  "))
        );
        // Height is half the width (two modules per row), rounded up.
        assert_eq!(rows.len(), width.div_ceil(2));
        // A finder pattern sits in the top-left corner.
        assert!(rows[1].chars().nth(2) == Some('█') || rows[1].chars().nth(2) == Some('▄'));
    }
}
