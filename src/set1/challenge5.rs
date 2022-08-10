use color_eyre::Result;
use rusty_pals::hex::to_hex;
use rusty_pals::xor::xor_with_key;

fn main() -> Result<()> {
    color_eyre::install()?;

    const INPUT: &str = "\
        Burning 'em, if you ain't quick and nimble\n\
        I go crazy when I hear a cymbal\
    ";

    let xorred = xor_with_key(INPUT, "ICE")?;
    let out = to_hex(&xorred);

    println!("{out}");

    assert_eq!(
        out,
        "0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D63343C2A26226324272765272\
        A282B2F20430A652E2C652A3124333A653E2B2027630C692B20283165286326302E27282F"
    );
    Ok(())
}
