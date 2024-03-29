use std::{fmt::Debug, io};

use anyhow::{anyhow, ensure, Context as _, Error, Result};

const COFF_HEADER_SIZE: usize = 0x18;
const OPTIONAL_HEADER_SIZE: usize = 0xF0;
const SECTION_HEADER_SIZE: usize = 40;
const IDT_ENTRY_SIZE: usize = 20;
const ILT_ENTRY_SIZE: usize = 8;
const EDT_TABLE_SIZE: usize = 40;

pub fn read_all(mut from: impl io::Read) -> Result<Vec<u8>> {
    let mut result = vec![];
    from.read_to_end(&mut result)
        .map(|_| result)
        .context("Error reading bytes")
}

fn get_subslice(slice: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    slice.get(offset..(offset + len))
}
fn get_fixed_subslice<const LEN: usize>(slice: &[u8], offset: usize) -> Option<&[u8; LEN]> {
    get_subslice(slice, offset, LEN).map(|slice| slice.try_into().unwrap())
}
fn get_u16(slice: &[u8], offset: usize) -> Option<u16> {
    get_fixed_subslice::<2>(slice, offset).map(|slice| u16::from_le_bytes(*slice))
}
fn get_u32(slice: &[u8], offset: usize) -> Option<u32> {
    get_fixed_subslice::<4>(slice, offset).map(|slice| u32::from_le_bytes(*slice))
}
fn get_u64(slice: &[u8], offset: usize) -> Option<u64> {
    get_fixed_subslice::<8>(slice, offset).map(|slice| u64::from_le_bytes(*slice))
}

fn strip_pe(data: &[u8]) -> Option<&[u8]> {
    get_u32(data, 0x3C).and_then(|pe_start| data.get((pe_start as usize)..))
}

#[allow(clippy::char_lit_as_u8)]
pub fn is_pe(file: &[u8]) -> bool {
    strip_pe(file).map(|pe| pe.get(0..4)) == Some(Some(&['P' as u8, 'E' as u8, 0, 0]))
}

fn get_optional_header(pe: &[u8]) -> Result<Option<&[u8; OPTIONAL_HEADER_SIZE]>> {
    let coff_header = get_fixed_subslice::<COFF_HEADER_SIZE>(pe, 0)
        .context("PE part is too short to contain a proper COFF Header")?;
    let size_of_optional_header = get_u16(coff_header, 0x14).unwrap() as usize;
    match size_of_optional_header {
        0 => Ok(None),
        OPTIONAL_HEADER_SIZE => {
            let optional_header = get_fixed_subslice::<OPTIONAL_HEADER_SIZE>(pe, COFF_HEADER_SIZE)
                .with_context(|| {
                    format!(
                        "Expected optional header to be at least {} bytes long, but found only {}",
                        OPTIONAL_HEADER_SIZE,
                        pe.len() - COFF_HEADER_SIZE
                    )
                })?;
            ensure!(
                optional_header.get(..2) == Some(&[0x0b, 0x02]),
                "Not a PE32+"
            );
            Ok(Some(optional_header))
        }
        unexpected => Err(anyhow!(
            "Unexpected size of optional header: {}",
            unexpected,
        )),
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

impl From<&[u8; SECTION_HEADER_SIZE]> for SectionHeader {
    fn from(raw: &[u8; SECTION_HEADER_SIZE]) -> Self {
        Self {
            name: *get_fixed_subslice::<8>(raw, 0x00).unwrap(),
            virtual_size: get_u32(raw, 0x08).unwrap(),
            virtual_address: get_u32(raw, 0x0c).unwrap(),
            size_of_raw_data: get_u32(raw, 0x10).unwrap(),
            pointer_to_raw_data: get_u32(raw, 0x14).unwrap(),
            pointer_to_relocations: get_u32(raw, 0x18).unwrap(),
            pointer_to_linenumbers: get_u32(raw, 0x1c).unwrap(),
            number_of_relocations: get_u16(raw, 0x20).unwrap(),
            number_of_line_numbers: get_u16(raw, 0x22).unwrap(),
            characteristics: get_u32(raw, 0x24).unwrap(),
        }
    }
}

fn get_section_headers(
    pe: &[u8],
    contains_optional_header: bool,
    number_of_sections: usize,
) -> Result<Vec<SectionHeader>> {
    let mut result = Vec::with_capacity(number_of_sections);
    for section_number in 0..number_of_sections {
        result.push(
            get_fixed_subslice::<SECTION_HEADER_SIZE>(
                pe,
                COFF_HEADER_SIZE
                    + if contains_optional_header {
                        OPTIONAL_HEADER_SIZE
                    } else {
                        0
                    }
                    + SECTION_HEADER_SIZE * section_number,
            )
            .with_context(|| {
                format!(
                    "Expected to read {} section headers, but there was enough data only for {}",
                    number_of_sections, section_number
                )
            })?
            .into(),
        )
    }
    Ok(result)
}

fn rva_to_raw(section_headers: &[SectionHeader], rva: u32) -> Result<usize> {
    section_headers
        .iter()
        .find(|section_header| {
            section_header.virtual_address <= rva
                && rva < section_header.virtual_address + section_header.virtual_size
        })
        .map(|section_header| {
            (section_header.pointer_to_raw_data + (rva - section_header.virtual_address)) as usize
        })
        .with_context(|| {
            format!(
                "Couldn't find the section that would contain rva 0x{:x}",
                rva
            )
        })
}

fn read_null_terminated_string(data: &[u8], start_offset: usize) -> Result<String> {
    let mut result = vec![];
    let mut current = start_offset;
    while let Some(&byte) = data.get(current) {
        if byte == 0 {
            return Ok(String::from_utf8(result)
                .unwrap_or_else(|_| format!("(non-ut8) {:?}", &data[start_offset..current])));
        } else {
            result.push(byte);
            current += 1
        }
    }
    Err(anyhow!(
        "EOF was reached before it was possible to read a null-terminated string \
        starting at offset 0x{:08x} ({} bytes read)",
        start_offset,
        current - start_offset
    ))
}

fn parse_ilt(
    file: &[u8],
    section_headers: &[SectionHeader],
    ilt_raw: usize,
) -> Result<Vec<String>> {
    let mut result = vec![];
    let mut ilt_entry_number = 0;
    while let Some(ilt_entry) = get_u64(file, ilt_raw + ilt_entry_number * ILT_ENTRY_SIZE) {
        if ilt_entry == 0 {
            return Ok(result);
        }
        if ilt_entry & (1 << 63) == 0 {
            let function_name_rva = ilt_entry as u32;
            let function_name_raw =
                rva_to_raw(section_headers, function_name_rva).with_context(|| {
                    format!(
                        "Error converting function name rva to raw offset for function #{}",
                        ilt_entry_number
                    )
                })?;
            result.push(
                read_null_terminated_string(file, function_name_raw + 2).with_context(|| {
                    format!(
                        "Error reading function name for function #{}",
                        ilt_entry_number
                    )
                })?,
            );
        }
        ilt_entry_number += 1;
    }
    Err(Error::msg(format!(
        "File abruptly ended at 0x{:x} bytes before it was possible \
        to read import lookup table entry #{} at 0x{:08x}",
        file.len(),
        ilt_entry_number,
        ilt_raw + ilt_entry_number * ILT_ENTRY_SIZE
    )))
}

fn parse_idt(
    file: &[u8],
    section_headers: &[SectionHeader],
    idt_raw: usize,
    idt_size: usize,
) -> Result<Vec<(String, Vec<String>)>> {
    let mut result = vec![];
    let mut idt_entry_number = 0;
    loop {
        ensure!(
            (idt_entry_number + 1) * IDT_ENTRY_SIZE <= idt_size,
            "Reading entry #{} from the import directory table \
            would exceed the size of the table ({} bytes)",
            idt_entry_number,
            idt_size
        );
        let idt_entry =
            get_fixed_subslice::<IDT_ENTRY_SIZE>(file, idt_raw + idt_entry_number * IDT_ENTRY_SIZE)
                .with_context(|| {
                    format!(
                        "File abruptly ended at 0x{:x} bytes before \
                        it was possible to read import directory table entry #{} at 0x{:08x}",
                        file.len(),
                        idt_entry_number,
                        idt_raw + idt_entry_number * IDT_ENTRY_SIZE
                    )
                })?;
        if idt_entry == &[0u8; IDT_ENTRY_SIZE] {
            return Ok(result);
        }
        let ilt_rva = get_u32(idt_entry, 0x00).unwrap();
        let dll_name_rva = get_u32(idt_entry, 0x0c).unwrap();
        let dll_name_raw = rva_to_raw(section_headers, dll_name_rva)
            .context("Error converting dll name rva to raw offset")?;
        result.push((
            read_null_terminated_string(file, dll_name_raw).context("Error reading dll name")?,
            parse_ilt(
                file,
                section_headers,
                rva_to_raw(section_headers, ilt_rva)
                    .context("Error converting ILR rva to raw offset")?,
            )
            .context("Error parsing ILT")?,
        ));
        idt_entry_number += 1;
    }
}

pub fn import_functions(file: &[u8]) -> Result<Vec<(String, Vec<String>)>> {
    let pe = strip_pe(file).context("File is too short to get its [0x3C..] part")?;
    let optional_header = get_optional_header(pe)
        .context("Error getting the optional header")?
        .context("Optional header is empty")?;
    let idt_rva = get_u32(optional_header, 0x78).unwrap();
    let idt_size = get_u32(optional_header, 0x7c).unwrap() as usize;
    let section_headers = get_section_headers(pe, true, get_u16(pe, 0x06).unwrap() as usize)
        .context("Error getting section headers")?;
    parse_idt(
        file,
        &section_headers,
        rva_to_raw(&section_headers, idt_rva).context("Error converting IDT rva to raw offset")?,
        idt_size,
    )
    .context("Error parsing IDT")
}

pub fn export_functions(file: &[u8]) -> Result<Vec<String>> {
    let pe = strip_pe(file).context("File is too short to get its [0x3C..] part")?;
    let optional_header = get_optional_header(pe)
        .context("Error getting the optional header")?
        .context("Optional header is empty")?;
    let edt_rva = get_u32(optional_header, 0x70).unwrap();
    let section_headers = get_section_headers(pe, true, get_u16(pe, 0x06).unwrap() as usize)
        .context("Error getting section headers")?;
    let edt_raw = rva_to_raw(&section_headers, edt_rva).context(
        "Error converting EDT rva to raw offset. \
        It may be possible that the given PE doesn't export any functions.",
    )?;
    let edt = get_fixed_subslice::<EDT_TABLE_SIZE>(file, edt_raw).with_context(|| {
        format!(
            "File abruptly ended before it was possible to read export directory table at 0x{:08x}",
            file.len(),
        )
    })?;
    let number_of_name_pointers = get_u32(edt, 24).unwrap() as usize;
    let npt_raw = rva_to_raw(&section_headers, get_u32(edt, 32).unwrap())
        .context("Error converting Name Pointer Table rva to raw offset")?;
    let mut result = Vec::with_capacity(number_of_name_pointers);
    for name_pointer_number in 0..number_of_name_pointers {
        let name_pointer_rva = get_u32(
            file,
            npt_raw + name_pointer_number * std::mem::size_of::<u32>(),
        )
        .with_context(|| {
            format!(
                "File abruptly ended at 0x{:x} bytes, before \
                it was even possible to read name pointer rva {}/{} at 0x{:08x}",
                file.len(),
                name_pointer_number,
                number_of_name_pointers,
                npt_raw + name_pointer_number * std::mem::size_of::<u32>(),
            )
        })?;
        let name_pointer_raw =
            rva_to_raw(&section_headers, name_pointer_rva).with_context(|| {
                format!(
                    "Error converting rva to raw offset for name pointer #{}",
                    name_pointer_number
                )
            })?;
        result.push(
            read_null_terminated_string(file, name_pointer_raw).with_context(|| {
                format!(
                    "Error reading function name for name pointer #{}",
                    name_pointer_number
                )
            })?,
        );
    }
    Ok(result)
}
