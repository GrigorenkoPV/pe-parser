use std::io;

pub fn err_to_string(err: impl std::fmt::Display) -> String {
    format!("{}", err)
}

pub fn read_all(mut from: impl io::Read) -> Result<Vec<u8>, String> {
    let mut result = vec![];
    from.read_to_end(&mut result)
        .map(|_| result)
        .map_err(|err| format!("{}", err))
}

pub fn is_pe(data: &[u8]) -> bool {
    data.get(0x3C..(0x3C + 4))
        .map(|slice| -> [u8; 4] { slice.try_into().unwrap() })
        .map(u32::from_le_bytes)
        .map(|i| i as usize)
        .map(|i| data.get(i..(i + 4)))
        == Some(Some(&['P' as u8, 'E' as u8, 0, 0]))
}
