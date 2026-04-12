use crate::{arch::amd64::scheduler::{sleep, syscall::{SyscallArguments, SyscallError}}, define_syscall_group};

define_syscall_group! {
    pub enum ThreadSyscallNums {
        ThreadSleep = 0x99,
        ThreadExit = 0x11
    }
}

fn thread_exit(self_id: u32, code: u64) -> ! {
    //let task = get_task_by_index(self_id as TaskIdIndex).expect("Task not found");
    //drop(task.addr_space.lock());
    todo!()
}

fn thread_sleep(ns: u64) -> Result<u64, SyscallError> {
    sleep(ns);

    Ok(0)
}

pub fn dispatch_thread_syscall_group(syscall: ThreadSyscallNums, curr_task_id: u32, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        ThreadSyscallNums::ThreadExit => thread_exit(curr_task_id, args.arg1),
        ThreadSyscallNums::ThreadSleep => thread_sleep(args.arg1)
    }
}