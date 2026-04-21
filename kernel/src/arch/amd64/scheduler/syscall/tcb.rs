use core::{cell::UnsafeCell, sync::atomic::{AtomicU32, AtomicU64, Ordering}};

use alloc::sync::Arc;
use spin::Mutex;

use crate::{arch::amd64::{ipc::{cnode::CNode, message::{Capability, Rights}, object_table::{KernelObjType, KernelObject, ObjData, obj_insert, with_object}}, memory::{u_k_boundary::uaccsess::{copy_from_user, copy_to_user}, vmm::{create_new_pt4_from_kernel_pt4}}, scheduler::{PerCpuSchedulerData, addr_space::AddrSpace, exec_loader::{phys_to_offset_page_table, user_task_trampoline}, stack::{DEFAULT_KERNEL_STACK_SIZE, allocate_kernel_stack}, syscall::{SyscallArguments, SyscallError, cap_check::resolve_cap}, task::{AtomicTaskState, Task, TaskRegisters, TaskState, Tcb}, task_storage::{get_task_by_index, global_queue, table}}}, define_syscall_group};

define_syscall_group! {
    pub enum TcbSyscallNumbers {
        TcbCreate = 1,
        TcbResume = 2,
        TcbSetRegs = 3,
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GrRegs {
    rax:    u64, 
    rbx:    u64,
    rcx:    u64,
    rdx:    u64,
    rsi:    u64,
    rdi:    u64,
    rbp:    u64,
    rsp:    u64,
    r8:     u64,
    r9:     u64,
    r10:    u64,
    r11:    u64,
    r12:    u64,
    r13:    u64,
    r14:    u64,
    r15:    u64,
    rip:    u64,
    rflags: u64,
}

fn tcb_set_regs(curr_task_id: u32, cap_tcb: u64, _type: u64, buff: u64) -> Result<u64, SyscallError> {
    let curr = get_task_by_index(curr_task_id).unwrap();

    let (handle_tcb, _rights) = match resolve_cap(&curr, cap_tcb, KernelObjType::Thread, Rights::ALL) {
        Ok(h) => h,
        Err(e) => return Err(e.to_syscall_error())
    };

    let target_task_id_by_tcb = match with_object(handle_tcb, |obj| {
        match &obj.data {
            ObjData::Thread(task_id) => Some(*task_id),
            _ => None,
        }
    }).flatten() {
        Some(id) => id,
        None => return Err(SyscallError::InvalidArgument),
    };

    if curr_task_id == target_task_id_by_tcb {
        return Err(SyscallError::PermissionDenied);
    }

    let general_regs = copy_from_user::<GrRegs>(buff as usize).ok_or(SyscallError::InvalidArgument)?;

    let task = get_task_by_index(target_task_id_by_tcb).expect("Task Not found");

    let stack_top_ptr = task.tcb.kernel_stack.top.as_u64() as *mut u64;

    unsafe {
        stack_top_ptr.sub(1).write(general_regs.rsp - 8);           
        stack_top_ptr.sub(2).write(general_regs.rip);           
        stack_top_ptr.sub(3).write(user_task_trampoline as u64);// ret
        for i in 4..=18 {
            stack_top_ptr.sub(i).write(0);
        }
        stack_top_ptr.sub(10).write(general_regs.rdi);            
    }

    let initial_rsp = unsafe { stack_top_ptr.sub(18) } as u64;

    unsafe { (*task.registers.get()).rsp = initial_rsp; }

    Ok(0)
}

#[derive(Clone, Copy)]
struct CreatedCapabilities {
    tcb_slot: u64,
    vspace_slot: u64,
    cnode_slot: u64
}

fn tcb_create(capabilities: u64) -> Result<u64, SyscallError> {
    static NEXT_ID: AtomicU32 = AtomicU32::new(2);
    let new_task_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

    let new_pml4_phys = create_new_pt4_from_kernel_pt4();
    let pt = phys_to_offset_page_table(new_pml4_phys);

    let task_def = Task {
        id: new_task_id,
        registers: UnsafeCell::new(TaskRegisters::default()),
        tcb: Tcb {
            wake_at_tick:  Mutex::new(AtomicU64::new(0)),
            addr_space:    Mutex::new(AddrSpace::new(pt)),
            kernel_stack:  allocate_kernel_stack(DEFAULT_KERNEL_STACK_SIZE),
            cnode:         Mutex::new(CNode::new()), 
            task_state:    AtomicTaskState::new(TaskState::Configuring),
            iopb_permissons: Mutex::new(None),
            iopb_gen: AtomicU64::new(0)
        }
    };

    let task_arc = Arc::new(task_def);

    let handle_tcb = obj_insert(KernelObject::new(
        KernelObjType::Thread,
        ObjData::Thread(task_arc.id),
    )).expect("Can not create handle");

    let cap_tcb = Capability::new(handle_tcb, Rights::ALL);

    let handle_vspace = obj_insert(KernelObject::new(
        KernelObjType::VSpace,
        ObjData::VSpace(task_arc.id),
    )).expect("Can not create handle");

    let cap_vspace = Capability::new(handle_vspace, Rights::ALL);

    let handle_cnode = obj_insert(KernelObject::new(
        KernelObjType::CNode,
        ObjData::CNode(task_arc.id),
    )).expect("Can not create handle");

    let cap_cnode = Capability::new(handle_cnode, Rights::ALL);

    let curr_task_id = PerCpuSchedulerData::get().curr_task_id;
    let curr = get_task_by_index(curr_task_id).unwrap();

    table().insert(task_arc);

    let tcb_slot = curr.tcb.cnode
        .lock()
        .alloc(cap_tcb).expect("Cnode is full") as u64;

    let vspace_slot = curr.tcb.cnode
        .lock()
        .alloc(cap_vspace).expect("Cnode is full") as u64;

    let cnode_slot = curr.tcb.cnode
        .lock()
        .alloc(cap_cnode).expect("Cnode is full") as u64;

    if !copy_to_user::<CreatedCapabilities>(capabilities as usize, CreatedCapabilities {
        tcb_slot,
        vspace_slot,
        cnode_slot
    }) {
        return Err(SyscallError::Fault);
    }

    Ok(0)
}

fn tcb_resume(tcb_cap: u64) -> Result<u64, SyscallError> {
    let curr_task_id = PerCpuSchedulerData::get().curr_task_id;
    let curr = get_task_by_index(curr_task_id).unwrap();

    let (handle_tcb, _rights) = match resolve_cap(&curr, tcb_cap, KernelObjType::Thread, Rights::ALL) {
        Ok(h) => h,
        Err(e) => return Err(e.to_syscall_error())
    };

    let target_task_id_by_tcb = match with_object(handle_tcb, |obj| {
        match &obj.data {
            ObjData::Thread(task_id) => Some(*task_id),
            _ => None,
        }
    }).flatten() {
        Some(id) => id,
        None => return Err(SyscallError::InvalidArgument),
    };

    if curr_task_id == target_task_id_by_tcb {
        return Err(SyscallError::PermissionDenied);
    }

    let task = get_task_by_index(target_task_id_by_tcb).expect("Task Not found");
    task.tcb.task_state.store(TaskState::Ready, Ordering::Release);
    global_queue().push(task);

    Ok(0)
}

pub fn dispatch_tcb_syscall_group(syscall: TcbSyscallNumbers, curr_task_id: u32, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        TcbSyscallNumbers::TcbCreate => tcb_create(args.arg1),
        TcbSyscallNumbers::TcbResume => tcb_resume(args.arg1),
        TcbSyscallNumbers::TcbSetRegs => tcb_set_regs(curr_task_id, args.arg1, args.arg2, args.arg3)
    }
}