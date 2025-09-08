use std::collections::HashMap;

// claude opus :blush:
pub fn lz_compress(input: &str) -> Vec<u8> {
    // Convert input string to byte array
    let mut input_bytes: Vec<u8> = input.as_bytes().to_vec();

    // Dictionary and compression state
    let mut string_to_code: HashMap<String, usize> = HashMap::new();
    let mut is_uncompressed: HashMap<String, bool> = HashMap::new();
    let mut current_string = String::new();
    let mut next_dict_size = 2;
    let mut next_dict_code = 3;
    let mut current_bit_width = 2;

    // Output buffer and bit manipulation
    let mut output_buffer: Vec<u8> = Vec::new();
    let mut bit_accumulator: u16 = 0;
    let mut bits_in_accumulator = 0;

    // Helper function to write bits to output buffer
    let write_bits = |_value: u32, bit_count: usize,
                          bit_accumulator: &mut u16,
                          bits_in_accumulator: &mut usize,
                          output_buffer: &mut Vec<u8>| {
        for _ in 0..bit_count {
            *bit_accumulator <<= 1;

            if *bits_in_accumulator == 15 {
                // Write 16 bits to output buffer when accumulator is full
                output_buffer.push((*bit_accumulator >> 8) as u8);
                output_buffer.push((*bit_accumulator & 255) as u8);
                *bits_in_accumulator = 0;
                *bit_accumulator = 0;
            } else {
                *bits_in_accumulator += 1;
            }
        }
    };

    // Helper function to write character bits (LSB first)
    let write_character_bits = |char_code: u8,
                                    bit_accumulator: &mut u16,
                                    bits_in_accumulator: &mut usize,
                                    output_buffer: &mut Vec<u8>| {
        let mut code = char_code;
        for _ in 0..8 {
            *bit_accumulator = ((code & 1) as u16) | (*bit_accumulator << 1);

            if *bits_in_accumulator == 15 {
                output_buffer.push((*bit_accumulator >> 8) as u8);
                output_buffer.push((*bit_accumulator & 255) as u8);
                *bits_in_accumulator = 0;
                *bit_accumulator = 0;
            } else {
                *bits_in_accumulator += 1;
            }

            code >>= 1;
        }
    };

    // Helper function to write dictionary code bits (LSB first)
    let write_dictionary_code_bits = |code: usize,
                                          current_bit_width: usize,
                                          bit_accumulator: &mut u16,
                                          bits_in_accumulator: &mut usize,
                                          output_buffer: &mut Vec<u8>| {
        let mut code_value = code;
        for _ in 0..current_bit_width {
            *bit_accumulator = (*bit_accumulator << 1) | (code_value & 1) as u16;

            if *bits_in_accumulator == 15 {
                output_buffer.push((*bit_accumulator >> 8) as u8);
                output_buffer.push((*bit_accumulator & 255) as u8);
                *bits_in_accumulator = 0;
                *bit_accumulator = 0;
            } else {
                *bits_in_accumulator += 1;
            }

            code_value >>= 1;
        }
    };

    // Helper function to check and update dictionary size
    let update_dictionary_size = |next_dict_size: &mut usize,
                                      current_bit_width: &mut usize| {
        *next_dict_size -= 1;
        if *next_dict_size == 0 {
            *next_dict_size = 2_usize.pow(*current_bit_width as u32);
            *current_bit_width += 1;
        }
    };

    // Main compression loop
    while !input_bytes.is_empty() {
        let current_byte = input_bytes.remove(0);
        let current_char = (current_byte as char).to_string();

        // Add character to dictionary if not present
        if !string_to_code.contains_key(&current_char) {
            string_to_code.insert(current_char.clone(), next_dict_code);
            next_dict_code += 1;
            is_uncompressed.insert(current_char.clone(), true);
        }

        let extended_string = format!("{}{}", current_string, current_char);

        if string_to_code.contains_key(&extended_string) {
            // Extended string exists in dictionary, continue building
            current_string = extended_string;
        } else {
            // Extended string not in dictionary, output current string
            if *is_uncompressed.get(&current_string).unwrap_or(&false) {
                // Output as uncompressed character
                let char_code = current_string.chars().next().unwrap() as u8;

                // Write bit width indicator
                write_bits(0, current_bit_width, &mut bit_accumulator,
                           &mut bits_in_accumulator, &mut output_buffer);

                // Write character bits
                write_character_bits(char_code, &mut bit_accumulator,
                                     &mut bits_in_accumulator, &mut output_buffer);

                update_dictionary_size(&mut next_dict_size, &mut current_bit_width);
                is_uncompressed.insert(current_string.clone(), false);
            } else {
                // Output as dictionary reference
                let dictionary_code = *string_to_code.get(&current_string).unwrap();
                write_dictionary_code_bits(dictionary_code, current_bit_width,
                                           &mut bit_accumulator, &mut bits_in_accumulator,
                                           &mut output_buffer);
            }

            update_dictionary_size(&mut next_dict_size, &mut current_bit_width);

            // Add new string to dictionary
            string_to_code.insert(extended_string, next_dict_code);
            next_dict_code += 1;
            current_string = current_char;
        }
    }

    // Handle remaining string
    if !current_string.is_empty() {
        if *is_uncompressed.get(&current_string).unwrap_or(&false) {
            let char_code = current_string.chars().next().unwrap() as u8;
            write_bits(0, current_bit_width, &mut bit_accumulator,
                       &mut bits_in_accumulator, &mut output_buffer);
            write_character_bits(char_code, &mut bit_accumulator,
                                 &mut bits_in_accumulator, &mut output_buffer);
            update_dictionary_size(&mut next_dict_size, &mut current_bit_width);
            is_uncompressed.insert(current_string.clone(), false);
        } else {
            let dictionary_code = *string_to_code.get(&current_string).unwrap();
            write_dictionary_code_bits(dictionary_code, current_bit_width,
                                       &mut bit_accumulator, &mut bits_in_accumulator,
                                       &mut output_buffer);
        }

        update_dictionary_size(&mut next_dict_size, &mut current_bit_width);
    }

    // Write end-of-stream marker
    let mut end_marker = 2;
    for _ in 0..current_bit_width {
        bit_accumulator = (bit_accumulator << 1) | (end_marker & 1) as u16;

        if bits_in_accumulator == 15 {
            output_buffer.push((bit_accumulator >> 8) as u8);
            output_buffer.push((bit_accumulator & 255) as u8);
            bits_in_accumulator = 0;
            bit_accumulator = 0;
        } else {
            bits_in_accumulator += 1;
        }

        end_marker >>= 1;
    }

    // Flush remaining bits
    loop {
        bit_accumulator <<= 1;

        if bits_in_accumulator == 15 {
            output_buffer.push((bit_accumulator >> 8) as u8);
            output_buffer.push((bit_accumulator & 255) as u8);
            break;
        }

        bits_in_accumulator += 1;
    }

    output_buffer
}