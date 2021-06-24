use std::convert::{TryInto, TryFrom};

use aya::{programs::SchedClassifier, Bpf, Pod};
use aya::programs::UProbe;
use aya::maps::{HashMap, Array};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}
#[derive(Copy, Clone,Debug)]
struct ReadlineEvent {
    pid:u32,
    str:[u8;80],
}

unsafe impl Pod for ReadlineEvent{

}

fn try_main() -> Result<(), anyhow::Error> {
    let code = include_bytes!("../aya-template-bpf/target/bpfel-unknown-none/debug/aya-template-bpf").to_vec();
    let mut bpf = aya::Bpf::load(&*code, None)?;
    let program: &mut UProbe = bpf.program_mut("get_return_value")?.try_into()?;
    program.load()?;
    program.attach(Some("readline"),0,"/bin/bash",  None)?;

    let mut arr =  Array::<_,ReadlineEvent>::try_from(bpf.map_mut("????")?)?;
    unsafe {
        loop {
            for el in arr.iter(){
                dbg!(el);
            }
        }
    }
    Ok(())
}
