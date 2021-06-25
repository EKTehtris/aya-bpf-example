#![no_std]
#![no_main]
#![allow(dead_code)]

use aya_bpf::{BpfContext, macros::uretprobe};
use aya_bpf::macros::map;
use aya_bpf::maps::PerfMap;
use aya_bpf_cty::{c_long, c_void};

#[panic_handler]
fn do_panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map]
static mut READLINE_EVENTS: PerfMap<ReadlineEvent> = PerfMap::new(0);

pub const MAX_LENGTH:usize=248;
#[repr(packed)]
struct ReadlineEvent {
    pid: u32,
    // 248 is the max I can fit with those alignement, for larger command split it
    str: [u8; MAX_LENGTH],
    r:c_long,
}

#[uretprobe(name = "get_return_value")]
fn process(ctx: aya_bpf::programs::ProbeContext) -> i32 {
    if ctx.regs.is_null() {
        return 0;
    }
    let pid = ctx.pid();
    let mut command = [0u8; MAX_LENGTH];
    let command_size: c_long = unsafe {
        aya_bpf_bindings::helpers::bpf_probe_read_str(command.as_mut_ptr() as *mut c_void, MAX_LENGTH as u32, (&*ctx.regs).rax as *const c_void)
    };
    unsafe {
        READLINE_EVENTS.output(&ctx, &ReadlineEvent {
            pid,
            str: command,
            r: command_size
        }, 0);
    }
    return 0;
}
