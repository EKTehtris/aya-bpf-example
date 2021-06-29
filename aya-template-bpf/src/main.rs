#![no_std]
#![no_main]
#![allow(dead_code)]

use aya_bpf::{BpfContext, macros::uretprobe};
use aya_bpf::macros::map;
use aya_bpf::maps::PerfMap;
use aya_bpf_cty::c_void;

#[panic_handler]
fn do_panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map]
static mut READLINE_EVENTS: PerfMap<ReadlineEvent> = PerfMap::new(0);

pub const MAX_LENGTH:usize=100;
#[repr(packed)]
struct ReadlineEvent {
    pid: u32,
    // 100 is a good compromise with that huge of a struct, use a different map for larger or chunk it
    str: [u8; MAX_LENGTH],
    ret:u64,
    parm1:u64,
    parm2:u64,
    parm3:u64,
    parm4:u64,
    parm5:u64,
    parm6:u64,
}

#[uretprobe(name = "get_return_value")]
fn process(ctx: aya_bpf::programs::ProbeContext) -> i32 {
    if ctx.regs.is_null() || ctx.regs.rc().is_null(){
        return 0;
    }
    let pid = ctx.pid();
    let mut command = [0u8; MAX_LENGTH];
    let ret: i64 = unsafe {
        aya_bpf_bindings::helpers::bpf_probe_read_str(command.as_mut_ptr() as *mut c_void, MAX_LENGTH as u32, ctx.regs.rc())
    };
    unsafe {
        READLINE_EVENTS.output(&ctx, &ReadlineEvent {
            pid,
            str: command,
            ret:ret as u64,
            parm1: ctx.regs.parm1(),
            parm2: ctx.regs.parm2(),
            parm3: ctx.regs.parm3(),
            parm4: ctx.regs.parm4(),
            parm5: ctx.regs.parm5(),
            parm6: ctx.regs.parm6(),
        }, 0);
    }
    return 0;
}
