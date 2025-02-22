use std::{
    io,
    path::{Path, PathBuf},
};

use crate::{
    encoding::Decodable,
    util::{cast_as_array, cast_as_arrays},
};

use super::Block;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    count: u64,
    key: Vec<u8>,
    iv: Option<Block>,
    operation: Operation,
    question_blocks: Vec<Block>,
}

pub type Answer = Vec<Block>;

#[derive(Debug, Clone)]
pub struct KnownAnswerTest {
    tests: Vec<(Question, Answer)>,
    loaded_from: PathBuf,
}

impl KnownAnswerTest {
    pub fn load(name: impl AsRef<Path>) -> io::Result<Self> {
        let response_file = Path::new("../vectors/AES").join(name);
        let mut contents = std::fs::read_to_string(&response_file)?;
        contents.retain(|c| c != '\r');

        let mut operation = Operation::Encrypt;
        let mut tests = vec![];
        for block in contents.split("\n\n") {
            dbg!(block);
            if block.starts_with('#') {
                continue;
            }

            if block == "[ENCRYPT]" {
                operation = Operation::Encrypt;
                continue;
            } else if block == "[DECRYPT]" {
                operation = Operation::Decrypt;
                continue;
            }

            if block.is_empty() {
                continue;
            }

            let mut count = None;
            let mut key = None;
            let mut iv = None;
            let mut pt = None;
            let mut ct = None;
            for line in block.lines() {
                let (name, value) = dbg!(line.split_once(" = ").unwrap());

                match name {
                    "COUNT" => count = value.parse().ok(),
                    "KEY" => key = value.decode_hex().ok(),
                    "IV" => iv = value.decode_hex().ok().map(|iv| *cast_as_array(&iv)),
                    "PLAINTEXT" => {
                        pt = value
                            .decode_hex()
                            .ok()
                            .map(|pt| cast_as_arrays(&pt).to_vec())
                    }
                    "CIPHERTEXT" => {
                        ct = value
                            .decode_hex()
                            .ok()
                            .map(|pt| cast_as_arrays(&pt).to_vec())
                    }

                    _ => panic!("Unexpected key: {name:?}"),
                }
            }

            match operation {
                Operation::Encrypt => tests.push((
                    Question {
                        count: count.unwrap(),
                        key: key.unwrap(),
                        iv,
                        question_blocks: pt.unwrap(),
                        operation,
                    },
                    ct.unwrap(),
                )),
                Operation::Decrypt => tests.push((
                    Question {
                        count: count.unwrap(),
                        key: key.unwrap(),
                        iv,
                        question_blocks: ct.unwrap(),
                        operation,
                    },
                    pt.unwrap(),
                )),
            }
        }

        Ok(Self {
            tests,
            loaded_from: response_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_answer_test_load_cbcgfsbox128() {
        let test = KnownAnswerTest::load("CBC/CBCGFSbox128.rsp").unwrap();

        assert_eq!(
            test.tests[0],
            (
                Question {
                    count: 0,
                    key: vec![0; 16],
                    iv: Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    question_blocks: vec![[
                        243, 68, 129, 236, 60, 198, 39, 186, 205, 93, 195, 251, 8, 242, 115, 230
                    ]],
                    operation: Operation::Encrypt,
                },
                vec![[3, 54, 118, 62, 150, 109, 146, 89, 90, 86, 124, 201, 206, 83, 127, 94]]
            )
        );

        assert_eq!(
            test.tests[1],
            (
                Question {
                    count: 1,
                    key: vec![0; 16],
                    iv: Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    question_blocks: vec![[
                        151, 152, 196, 100, 11, 173, 117, 199, 195, 34, 125, 185, 16, 23, 78, 114
                    ]],
                    operation: Operation::Encrypt,
                },
                vec![[169, 161, 99, 27, 244, 153, 105, 84, 235, 192, 147, 149, 123, 35, 69, 137]]
            )
        );

        assert_eq!(
            test.tests[7],
            (
                Question {
                    count: 0,
                    key: vec![0; 16],
                    iv: Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    question_blocks: vec![[
                        3, 54, 118, 62, 150, 109, 146, 89, 90, 86, 124, 201, 206, 83, 127, 94
                    ]],
                    operation: Operation::Decrypt,
                },
                vec![[243, 68, 129, 236, 60, 198, 39, 186, 205, 93, 195, 251, 8, 242, 115, 230]]
            )
        );
    }

    #[test]
    fn test_known_answer_test_load_ecbmmt192() {
        let test = KnownAnswerTest::load("ECB/ECBMMT192.rsp").unwrap();

        assert_eq!(
            test.tests[3],
            (
                Question {
                    count: 3,
                    key: "3deecf7a037ebb2ada805e8059bfaeaebb195cace379fcd2"
                        .decode_hex()
                        .unwrap(),
                    iv: None,
                    question_blocks: vec![
                        [9, 102, 18, 244, 17, 30, 189, 185, 172, 207, 94, 251, 185, 115, 88, 158],
                        [90, 44, 145, 3, 64, 126, 210, 218, 41, 188, 113, 55, 166, 192, 45, 232],
                        [34, 223, 89, 7, 32, 29, 61, 203, 196, 156, 185, 163, 149, 91, 43, 134],
                        [
                            129, 29, 147, 132, 34, 166, 245, 162, 63, 45, 255, 228, 150, 15, 236,
                            171
                        ],
                    ],
                    operation: Operation::Encrypt,
                },
                vec![
                    [211, 117, 225, 175, 95, 205, 3, 227, 29, 15, 115, 95, 107, 197, 215, 231],
                    [115, 188, 52, 255, 62, 183, 6, 190, 133, 132, 47, 153, 142, 78, 54, 19],
                    [3, 130, 91, 132, 129, 112, 96, 143, 48, 10, 209, 206, 216, 72, 181, 35],
                    [52, 119, 245, 55, 16, 80, 60, 85, 115, 106, 115, 5, 149, 89, 153, 100]
                ]
            )
        );
    }
}
