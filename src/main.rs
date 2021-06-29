#![allow(unaligned_references,unreachable_code)]

use std::convert::{TryFrom, TryInto};
use std::fmt;

use aya::Pod;
use aya::maps::PerfEventArray;
use aya::programs::UProbe;
use aya::util::online_cpus;
use bytes::BytesMut;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}
pub const MAX_LENGTH:usize=100;
#[derive(Copy, Clone, Debug)]
#[repr(packed)]
struct ReadlineEvent {
    pid: u32,
    str: [u8; MAX_LENGTH],
    ret:u64,
    parm1:u64,
    parm2:u64,
    parm3:u64,
    parm4:u64,
    parm5:u64,
    parm6:u64,
}

pub fn str_from_u8_nul_utf8(utf8_src: &[u8]) -> Result<&str, std::str::Utf8Error> {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len()); // default to length if no `\0` present
    ::std::str::from_utf8(&utf8_src[0..nul_range_end])
}

impl fmt::Display for ReadlineEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{},{},{},{},{},{},{}, {:?})",
               self.pid, self.ret,self.parm1,self.parm2,self.parm3,self.parm4,self.parm5,self.parm6, str_from_u8_nul_utf8(self.str.as_ref()).unwrap_or("Error"))
    }
}

unsafe impl Pod for ReadlineEvent {}


fn try_main() -> Result<(), anyhow::Error> {
    let code = include_bytes!("../aya-template-bpf/target/bpfel-unknown-none/debug/aya-template-bpf").to_vec();
    let mut bpf = aya::Bpf::load(&*code, None)?;
    let program: &mut UProbe = bpf.program_mut("get_return_value")?.try_into()?;
    program.load()?;
    program.attach(Some("readline"), 0, "/bin/bash", None)?;

    let mut perf_array = PerfEventArray::try_from(bpf.map_mut("READLINE_EVENTS")?)?;

    // eBPF programs are going to write to the EVENTS perf array, using the id of the CPU they're
    // running on as the array index.
    let mut perf_buffers = Vec::new();
    for cpu_id in online_cpus()? {
        // this perf buffer will receive events generated on the CPU with id cpu_id
        perf_buffers.push(perf_array.open(cpu_id, None)?);
    }

    let mut out_bufs = [BytesMut::with_capacity(1024)];

    loop {
        for buffer in perf_buffers.iter_mut() {
            if buffer.readable() {
                let r = buffer.read_events(&mut out_bufs)?;
                dbg!(r);
                let (head, body, _tail) = unsafe { out_bufs.get(0).unwrap().align_to::<ReadlineEvent>() };
                if !head.is_empty() {
                    eprintln!("Data not aligned");
                }
                println!("{}", body.get(0).unwrap());
            }
        }
    }
    Ok(())
}
