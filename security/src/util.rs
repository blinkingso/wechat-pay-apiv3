use rand::thread_rng;
use rand::Rng;

pub fn random_string(count: usize) -> String {
    random(count, 32, 126, false, false, None)
}

pub fn random(
    count: usize,
    start: u32,
    end: u32,
    letters: bool,
    numbers: bool,
    chars: Option<&Vec<char>>,
) -> String {
    let mut random = thread_rng();
    if count == 0 {
        return String::new();
    }
    if chars.is_some() && chars.as_ref().unwrap().is_empty() {
        return String::new();
    }
    let mut start = start;
    let mut end = end;
    if start == 0 && end == 0 {
        if let Some(chars) = chars {
            end = chars.len() as u32;
        } else {
            if !letters && !numbers {
                // no letter and numbers allowed.
                end = char::MAX as u32;
            } else {
                end = 'z' as u32 + 1;
                start = ' ' as u32;
            }
        }
    } else if end <= start {
        return String::new();
    }
    let zero_digit_ascii = 48_u32;
    let first_letter_ascii = 65_u32;
    if chars.is_none()
        && (numbers && end <= zero_digit_ascii || letters && end <= first_letter_ascii)
    {
        return String::new();
    }

    let mut res = String::new();
    let mut count = count;
    let gap = end - start;
    while count != 0 {
        count -= 1;
        let code_point = match chars {
            Some(chars) => chars
                .get((random.gen_range(0..gap) + start) as usize)
                .unwrap()
                .clone(),
            None => {
                let code_point = (random.gen_range(0..gap) + start) as u32;
                match char::from_u32(code_point) {
                    Some(ch) if !ch.is_ascii_alphanumeric() => {
                        count += 1;
                        continue;
                    }
                    None => {
                        count += 1;
                        continue;
                    }
                    Some(ch) => ch,
                }
            }
        };
        let number_of_chars = code_point.len_utf8();
        if count == 0 && number_of_chars > 1 {
            count += 1;
            continue;
        }

        if letters && code_point.is_ascii_alphabetic()
            || numbers && code_point.is_ascii_digit()
            || !letters && !numbers
        {
            res.push(code_point);

            if number_of_chars == 2 {
                count -= 1;
            }
        } else {
            count += 1;
        }
    }
    res
}
