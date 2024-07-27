use crate::Error;
use regex::Regex;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub struct AnsiCat {
    pub ansi_lines: Vec<String>,
}

impl AnsiCat {
    pub fn load(src: String) -> Result<AnsiCat, Box<Error>> {
        let ansi_lines = read_lines(&src).unwrap();

        let mut max_width = 0;
        // let mut height = 0;

        for line in &ansi_lines {
            // Strip ANSI codes for dimension calculation
            let stripped_line = strip_ansi_codes(line);
            let width = stripped_line.char_indices().count();
            // if width > 0 {
            //     height += 1;
            // }
            if width > max_width {
                max_width = width;
            }
        }

        // Create a new AnsiCat instance
        let cat = AnsiCat {
            ansi_lines: ansi_lines,
        };

        Ok(cat)
    }

    pub fn talk(&self, x: usize, y: usize, text: String) -> &'static str {
        let mut output = String::new();
        let color_code_start = "\x1b[96m"; // Bright cyan color
        let color_code_end = "\x1b[0m"; // Reset color

        for (i, line) in self.ansi_lines.iter().enumerate() {
            if i == y {
                let mut stripped_line = strip_ansi_codes(line);
                let text_char_length = stripped_line.char_indices().count();
                if x < text_char_length {
                    let text_len = text.len();
                    let x_position = stripped_line.char_indices().nth(x).unwrap().0;

                    let last_position = if x + text_len < text_char_length - 1 {
                        stripped_line.char_indices().nth(x + text_len).unwrap().0
                    } else {
                        stripped_line.len()
                    };

                    let replace_range = x_position..last_position;

                    // Insert the colored text into the stripped line at the correct position
                    let colored_text = format!("{}{}{}", color_code_start, text, color_code_end);
                    stripped_line.replace_range(replace_range, &colored_text);
                    output.push_str(&format!("{}\n", stripped_line));
                } else {
                    output.push_str(&format!("{}\n", line));
                }
            } else {
                output.push_str(&format!("{}\n", line));
            }
        }

        // Leak the memory to extend the lifetime to 'static
        Box::leak(output.into_boxed_str())
    }
}

// Function to read lines from a file and return a vector of strings
fn read_lines<P>(filename: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    reader.lines().collect()
}

// Function to strip ANSI escape sequences from a string
// ANSI escape codes are used to control formatting, color, and other output options on text terminals.
// These codes typically start with the escape character \x1b (which is the hexadecimal representation of 27)
// followed by [ and then a series of numbers and semicolons, ending with the letter m.
fn strip_ansi_codes(input: &str) -> String {
    let re = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    re.replace_all(input, "").to_string()
}
