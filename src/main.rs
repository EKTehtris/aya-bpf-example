use std::convert::{TryFrom, TryInto};
use std::ops::DerefMut;

use aya::{Bpf, Pod, programs::SchedClassifier};
use aya::maps::{Array, HashMap, PerfEventArray};
use aya::maps::Map;
use aya::maps::perf::PerfEventArrayBuffer;
use aya::programs::UProbe;
use aya::util::online_cpus;
use bytes::BytesMut;
use std::os::unix::io::AsRawFd;
use std::fmt::{Display, Formatter};
use std::fmt;
use std::ffi::CStr;
use std::os::raw::c_long;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(packed)]
struct ReadlineEvent {
    pid: u32,
    str: [u8; 80],
    r:c_long,
}
impl fmt::Display for ReadlineEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{}, {:?})", self.pid,self.r, String::from_utf8_lossy(self.str.as_ref())
        )
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
        for buffer in perf_buffers.iter_mut(){
            if buffer.readable() {
                let r=buffer.read_events(&mut out_bufs)?;
                // let a=out_bufs.clone();
                // let array=a.get(0).unwrap();
                let (head, body, _tail) = unsafe { out_bufs.get(0).unwrap().align_to::<ReadlineEvent>() };
                if !head.is_empty(){
                    eprintln!("Data not aligned");
                }
                println!("{}",body.get(0).unwrap());
            }
        }
    }
    Ok(())
}
