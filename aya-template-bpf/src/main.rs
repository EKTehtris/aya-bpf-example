#![no_std]
#![no_main]

use aya_bpf::{bindings::TC_ACT_OK, BpfContext, macros::uretprobe, programs::SkSkbContext};
use aya_bpf::helpers::bpf_probe_read;
use aya_bpf::macros::map;
use aya_bpf::maps::PerfMap;
use aya_bpf::programs::ProbeContext;
use aya_bpf_bindings::helpers::bpf_probe_read_str;
use aya_bpf_cty::{c_long, c_void};
use aya_bpf_bindings::bindings::pt_regs;
use core::ptr;

#[panic_handler]
fn do_panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map]
static mut READLINE_EVENTS: PerfMap<ReadlineEvent> = PerfMap::new(0);

#[repr(packed)]
struct ReadlineEvent {
    pid: u32,
    str: [u8; 80],
    r:c_long,
}

#[uretprobe(name = "get_return_value")]
fn process(mut ctx: aya_bpf::programs::ProbeContext) -> i32 {
    if ctx.regs.is_null() {
        return 0;
    }
    let pid = ctx.pid();
    let mut str = [0u8; 80];

    let mut p;
    let r:&mut pt_regs = unsafe {
        p = ptr::NonNull::new(
            ctx.regs
        ).unwrap();
        p.as_mut()
    };
    let r: c_long = unsafe {
        aya_bpf_bindings::helpers::bpf_probe_read_str(str.as_mut_ptr() as *mut c_void, 80, r.rax as *const c_void)
    };
    unsafe {
        READLINE_EVENTS.output(&ctx, &ReadlineEvent {
            pid,
            str,
            r
        }, 0);
    }
    return 0;
}
