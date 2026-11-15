//! Bounded dependency extraction for ELF, PE and Mach-O binaries.
//! This module parses file-backed metadata only; it never loads or executes samples.
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DependencyReport {
    pub format: String,
    pub dependencies: Vec<String>,
    pub truncated: bool,
    pub parser_notes: Vec<String>,
}

fn range(bytes: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(length)?)
}
fn u16_at(bytes: &[u8], offset: usize, little: bool) -> Option<u16> {
    let v: [u8; 2] = range(bytes, offset, 2)?.try_into().ok()?;
    Some(if little { u16::from_le_bytes(v) } else { u16::from_be_bytes(v) })
}
fn u32_at(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
    let v: [u8; 4] = range(bytes, offset, 4)?.try_into().ok()?;
    Some(if little { u32::from_le_bytes(v) } else { u32::from_be_bytes(v) })
}
fn u64_at(bytes: &[u8], offset: usize, little: bool) -> Option<u64> {
    let v: [u8; 8] = range(bytes, offset, 8)?.try_into().ok()?;
    Some(if little { u64::from_le_bytes(v) } else { u64::from_be_bytes(v) })
}
fn as_usize(value: u64) -> Option<usize> { usize::try_from(value).ok() }

fn c_string(bytes: &[u8], offset: usize, max_len: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().take(max_len).position(|b| *b == 0)?;
    if end == 0 { return None; }
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn push_bounded(values: &mut Vec<String>, value: String, maximum: usize, truncated: &mut bool) {
    if values.len() < maximum { values.push(value); } else { *truncated = true; }
}

fn parse_elf(bytes: &[u8], maximum: usize) -> Option<DependencyReport> {
    if !bytes.starts_with(b"\x7fELF") { return None; }
    let class = *bytes.get(4)?;
    let little = match *bytes.get(5)? { 1 => true, 2 => false, _ => return None };
    if *bytes.get(6)? != 1 { return None; }
    let (shoff, shentsize, shnum, min_size) = match class {
        1 => (u64::from(u32_at(bytes, 32, little)?), usize::from(u16_at(bytes, 46, little)?), usize::from(u16_at(bytes, 48, little)?), 40usize),
        2 => (u64_at(bytes, 40, little)?, usize::from(u16_at(bytes, 58, little)?), usize::from(u16_at(bytes, 60, little)?), 64usize),
        _ => return None,
    };
    if shnum == 0 || shentsize < min_size { return None; }
    let start = as_usize(shoff)?;
    let table_len = shentsize.checked_mul(shnum)?;
    range(bytes, start, table_len)?;

    let mut sections = Vec::with_capacity(shnum);
    for index in 0..shnum {
        let base = start.checked_add(index.checked_mul(shentsize)?)?;
        let (kind, offset, size, link, entsize) = if class == 1 {
            (u32_at(bytes, base + 4, little)?, u64::from(u32_at(bytes, base + 16, little)?),
             u64::from(u32_at(bytes, base + 20, little)?), u32_at(bytes, base + 24, little)?,
             u64::from(u32_at(bytes, base + 36, little)?))
        } else {
            (u32_at(bytes, base + 4, little)?, u64_at(bytes, base + 24, little)?,
             u64_at(bytes, base + 32, little)?, u32_at(bytes, base + 40, little)?,
             u64_at(bytes, base + 56, little)?)
        };
        sections.push((kind, offset, size, link, entsize));
    }

    let mut dependencies = Vec::new();
    let mut truncated = false;
    for (kind, offset, size, link, entsize) in sections.iter().copied().filter(|v| v.0 == 6) {
        let dynstr_index = usize::try_from(link).ok()?;
        let (_, str_offset, str_size, _, _) = *sections.get(dynstr_index)?;
        let str_start = as_usize(str_offset)?;
        let str_bytes = range(bytes, str_start, as_usize(str_size)?)?;
        let entry_size = if entsize == 0 { if class == 1 { 8 } else { 16 } } else { as_usize(entsize)? };
        let minimum = if class == 1 { 8 } else { 16 };
        if entry_size < minimum { return None; }
        let dyn_start = as_usize(offset)?;
        let dyn_bytes = as_usize(size)?;
        let dynamic = range(bytes, dyn_start, dyn_bytes)?;
        for entry in dynamic.chunks_exact(entry_size) {
            let tag = if class == 1 {
                i64::from(u32_at(entry, 0, little)? as i32)
            } else {
                u64_at(entry, 0, little)? as i64
            };
            if tag == 0 { break; }
            if tag == 1 {
                let name_offset = if class == 1 { u64::from(u32_at(entry, 4, little)?) } else { u64_at(entry, 8, little)? };
                let name_offset = as_usize(name_offset)?;
                if let Some(name) = c_string(str_bytes, name_offset, 4096) {
                    push_bounded(&mut dependencies, name, maximum, &mut truncated);
                }
            }
        }
    }
    dependencies.sort();
    dependencies.dedup();
    Some(DependencyReport {
        format: if class == 1 { "elf32" } else { "elf64" }.into(),
        dependencies,
        truncated,
        parser_notes: vec!["DT_NEEDED entries were read from bounded SHT_DYNAMIC sections.".into()],
    })
}

fn rva_to_offset(rva: u32, sections: &[(u32, u32, u32, u32)], headers_size: usize) -> Option<usize> {
    if (rva as usize) < headers_size { return Some(rva as usize); }
    for (virtual_address, virtual_size, raw_offset, raw_size) in sections {
        let span = (*virtual_size).max(*raw_size);
        if rva >= *virtual_address && rva.checked_sub(*virtual_address)? < span {
            let delta = rva.checked_sub(*virtual_address)?;
            if delta >= *raw_size { return None; }
            return usize::try_from(raw_offset.checked_add(delta)?).ok();
        }
    }
    None
}

fn parse_pe(bytes: &[u8], maximum: usize) -> Option<DependencyReport> {
    if !bytes.starts_with(b"MZ") { return None; }
    let pe = usize::try_from(u32_at(bytes, 0x3c, true)?).ok()?;
    if range(bytes, pe, 4)? != b"PE\0\0" { return None; }
    let coff = pe.checked_add(4)?;
    let section_count = usize::from(u16_at(bytes, coff + 2, true)?);
    let optional_size = usize::from(u16_at(bytes, coff + 16, true)?);
    let optional = coff.checked_add(20)?;
    let magic = u16_at(bytes, optional, true)?;
    let (directory_base, pointer_width) = match magic {
        0x10b => (96usize, 4usize),
        0x20b => (112usize, 8usize),
        _ => return None,
    };
    let headers_size = usize::try_from(u32_at(bytes, optional + 60, true)?).ok()?;
    if optional_size < directory_base + 16 { return None; }
    let import_rva = u32_at(bytes, optional + directory_base + 8, true)?;
    let import_size = u32_at(bytes, optional + directory_base + 12, true)?;
    let section_table = optional.checked_add(optional_size)?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let base = section_table.checked_add(index.checked_mul(40)?)?;
        range(bytes, base, 40)?;
        sections.push((
            u32_at(bytes, base + 12, true)?,
            u32_at(bytes, base + 8, true)?,
            u32_at(bytes, base + 20, true)?,
            u32_at(bytes, base + 16, true)?,
        ));
    }
    let mut dependencies = Vec::new();
    let mut truncated = false;
    if import_rva != 0 && import_size >= 20 {
        let directory = rva_to_offset(import_rva, &sections, headers_size)?;
        let max_descriptors = (import_size as usize / 20).min(4096);
        for index in 0..max_descriptors {
            let base = directory.checked_add(index.checked_mul(20)?)?;
            let descriptor = range(bytes, base, 20)?;
            let original_thunk = u32_at(descriptor, 0, true)?;
            let name_rva = u32_at(descriptor, 12, true)?;
            let first_thunk = u32_at(descriptor, 16, true)?;
            if original_thunk == 0 && name_rva == 0 && first_thunk == 0 { break; }
            let name_offset = rva_to_offset(name_rva, &sections, headers_size)?;
            if let Some(name) = c_string(bytes, name_offset, 4096) {
                push_bounded(&mut dependencies, name, maximum, &mut truncated);
            }
        }
    }
    dependencies.sort();
    dependencies.dedup();
    Some(DependencyReport {
        format: if pointer_width == 4 { "pe32" } else { "pe32_plus" }.into(),
        dependencies,
        truncated,
        parser_notes: vec!["PE import directory library names were parsed; individual imported symbols are not yet resolved.".into()],
    })
}

fn parse_macho(bytes: &[u8], maximum: usize) -> Option<DependencyReport> {
    let magic: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let (little, is_64) = match magic {
        [0xce, 0xfa, 0xed, 0xfe] => (true, false),
        [0xcf, 0xfa, 0xed, 0xfe] => (true, true),
        [0xfe, 0xed, 0xfa, 0xce] => (false, false),
        [0xfe, 0xed, 0xfa, 0xcf] => (false, true),
        _ => return None,
    };
    let header_size = if is_64 { 32usize } else { 28usize };
    let command_count = usize::try_from(u32_at(bytes, 16, little)?).ok()?;
    let command_bytes = usize::try_from(u32_at(bytes, 20, little)?).ok()?;
    let command_end = header_size.checked_add(command_bytes)?;
    range(bytes, header_size, command_bytes)?;
    let mut cursor = header_size;
    let mut dependencies = Vec::new();
    let mut truncated = false;
    for _ in 0..command_count.min(65_536) {
        if cursor >= command_end { break; }
        let command = u32_at(bytes, cursor, little)?;
        let size = usize::try_from(u32_at(bytes, cursor + 4, little)?).ok()?;
        if size < 8 || cursor.checked_add(size)? > command_end { return None; }
        let dylib_command = matches!(command, 0x0c | 0x18 | 0x1f | 0x20 | 0x80000018 | 0x8000001f | 0x80000023);
        if dylib_command && size >= 24 {
            let name_offset = usize::try_from(u32_at(bytes, cursor + 8, little)?).ok()?;
            if name_offset < size {
                if let Some(name) = c_string(bytes, cursor + name_offset, size - name_offset) {
                    push_bounded(&mut dependencies, name, maximum, &mut truncated);
                }
            }
        }
        cursor += size;
    }
    dependencies.sort();
    dependencies.dedup();
    Some(DependencyReport {
        format: if is_64 { "macho64" } else { "macho32" }.into(),
        dependencies,
        truncated,
        parser_notes: vec!["Mach-O dylib load commands were inspected; rpaths and symbol bindings are not yet resolved.".into()],
    })
}

/// Extract bounded shared-library dependencies without executing the artifact.
pub fn extract_dependencies(bytes: &[u8], maximum: usize) -> Option<DependencyReport> {
    if maximum == 0 { return None; }
    parse_elf(bytes, maximum)
        .or_else(|| parse_pe(bytes, maximum))
        .or_else(|| parse_macho(bytes, maximum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_or_invalid_executable_headers() {
        assert!(extract_dependencies(b"\x7fELF", 100).is_none());
        assert!(extract_dependencies(b"MZ", 100).is_none());
        assert!(extract_dependencies(b"\xcf\xfa\xed\xfe", 100).is_none());
        assert!(extract_dependencies(b"plain text", 100).is_none());
    }

    #[test]
    fn extracts_elf_dt_needed_library_names() {
        let mut bytes = vec![0u8; 298];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[40..48].copy_from_slice(&64u64.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&3u16.to_le_bytes());

        // SHT_STRTAB at section index 1.
        bytes[128 + 4..128 + 8].copy_from_slice(&3u32.to_le_bytes());
        bytes[128 + 24..128 + 32].copy_from_slice(&256u64.to_le_bytes());
        bytes[128 + 32..128 + 40].copy_from_slice(&10u64.to_le_bytes());

        // SHT_DYNAMIC at section index 2, linked to section 1.
        bytes[192 + 4..192 + 8].copy_from_slice(&6u32.to_le_bytes());
        bytes[192 + 24..192 + 32].copy_from_slice(&266u64.to_le_bytes());
        bytes[192 + 32..192 + 40].copy_from_slice(&32u64.to_le_bytes());
        bytes[192 + 40..192 + 44].copy_from_slice(&1u32.to_le_bytes());
        bytes[192 + 56..192 + 64].copy_from_slice(&16u64.to_le_bytes());

        bytes[256..266].copy_from_slice(b"\0libc.so\0");
        bytes[266..274].copy_from_slice(&1i64.to_le_bytes());
        bytes[274..282].copy_from_slice(&1u64.to_le_bytes());
        bytes[282..290].copy_from_slice(&0i64.to_le_bytes());

        let report = extract_dependencies(&bytes, 10).unwrap();
        assert_eq!(report.format, "elf64");
        assert_eq!(report.dependencies, vec!["libc.so"]);
    }

    #[test]
    fn parses_minimal_pe_without_import_directory() {
        let mut bytes = vec![0u8; 0x200];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        let optional = 0x98;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let report = extract_dependencies(&bytes, 20).unwrap();
        assert_eq!(report.format, "pe32_plus");
        assert!(report.dependencies.is_empty());
    }
}
