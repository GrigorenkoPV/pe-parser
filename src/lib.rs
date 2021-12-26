use std::io;

pub type Res<T> = Result<T, String>;

const COFF_HEADER_SIZE: usize = 0x18;
const OPTIONAL_HEADER_SIZE: usize = 0xF0;
const SECTION_HEADER_SIZE: usize = 40;

pub fn err_to_string(err: impl std::fmt::Display) -> String {
    format!("{}", err)
}

pub fn read_all(mut from: impl io::Read) -> Res<Vec<u8>> {
    let mut result = vec![];
    from.read_to_end(&mut result)
        .map(|_| result)
        .map_err(err_to_string)
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

fn strip_pe(data: &[u8]) -> Option<&[u8]> {
    get_u32(data, 0x3C)
        .map(|pe_start| data.get((pe_start as usize)..))
        .flatten()
}

pub fn is_pe(data: &[u8]) -> bool {
    strip_pe(data).map(|pe| pe.get(0..4)) == Some(Some(&['P' as u8, 'E' as u8, 0, 0]))
}

fn get_optional_header(pe: &[u8]) -> Res<Option<&[u8; OPTIONAL_HEADER_SIZE]>> {
    let coff_header = get_fixed_subslice::<COFF_HEADER_SIZE>(pe, 0)
        .ok_or("PE part too short to contain a proper COFF Header".to_string())?;
    let size_of_optional_header = get_u16(coff_header, 0x14).unwrap() as usize;
    match size_of_optional_header {
        0 => Ok(None),
        OPTIONAL_HEADER_SIZE => {
            match get_fixed_subslice::<OPTIONAL_HEADER_SIZE>(pe, COFF_HEADER_SIZE) {
                Some(optional_header) => {
                    if optional_header.get(..2) != Some(&[0x0b, 0x02]) {
                        Err("Not a PE32+".to_string())
                    } else {
                        Ok(Some(optional_header))
                    }
                }
                None => Err(format!(
                    "Expected optional header to be at least {} bytes long, but found only {}",
                    OPTIONAL_HEADER_SIZE,
                    pe.len() - COFF_HEADER_SIZE
                )),
            }
        }
        _ => Err(format!(
            "Unexpected size of optional header: {}",
            size_of_optional_header
        )),
    }
}

fn get_section_headers(
    pe: &[u8],
    contains_optional_header: bool,
    number_of_sections: usize,
) -> Res<Vec<&[u8; SECTION_HEADER_SIZE]>> {
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
            .ok_or(format!(
                "Expected to read {} section headers, but there was enough data only to read {}",
                number_of_sections, section_number
            ))?,
        )
    }
    Ok(result)
}

pub fn import_functions(data: &[u8]) -> Res<()> {
    let pe = strip_pe(data).ok_or("File too short to get its [0x3C].. part".to_string())?;
    let optional_header = get_optional_header(pe)?.ok_or("Optional header is empty".to_string())?;
    let import_table_rva = get_u32(optional_header, 0x78).unwrap();
    dbg!(import_table_rva);
    let number_of_sections = get_u16(pe, 0x06).unwrap() as usize;
    let section_headers = get_section_headers(pe, true, number_of_sections)?;
    todo!()
}
