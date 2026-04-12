use crate::arch::amd64::scheduler::{sleep, task::{TaskId, TaskIdIndex}, task_storage::get_task_by_index};

#[repr(u64)]
pub enum ThreadSyscallNums {
    ThreadSleep = 0x99,
    ThreadExit = 0x11
}

impl TryFrom<u64> for ThreadSyscallNums {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::ThreadSleep as u64 => Ok(Self::ThreadSleep),
            x if x == Self::ThreadExit as u64 => Ok(Self::ThreadExit),
            _ => Err(()),
        }
    }
}

pub (crate) fn thread_exit(self_id: u64, code: u64) -> ! {
    //let task = get_task_by_index(self_id as TaskIdIndex).expect("Task not found");
    //drop(task.addr_space.lock());
    todo!()
}

pub (crate) fn thread_sleep(ns: u64) -> i64 {
    sleep(ns);

    0
}