#![no_std]
#![no_main]

use aya_bpf::{bindings::TC_ACT_OK, macros::uretprobe, programs::SkSkbContext, BpfContext};
use aya_bpf::helpers::bpf_probe_read;
use aya_bpf::maps::PerfMap;

#[panic_handler]
fn do_panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[repr(packed)]
struct ReadlineEvent {
    pid:u32,
    str:[u8;80],
}

#[uretprobe(name = "get_return_value")]
fn process(mut ctx:aya_bpf::programs::ProbeContext) ->i32{
    if ctx.regs.is_null() {
        return 0;
    }
    let pid=ctx.pid();
    let str=[0u8;80];
    let r:Result<[u8;80],i64>=unsafe{bpf_probe_read(&str)};

    if r.is_ok() {
        let mut perfmap =PerfMap::new(0);
        perfmap.output(&ctx, &ReadlineEvent{
            pid,
            str: r.unwrap()
        }, 0);
        return 0;
    }
    return 1;
}
