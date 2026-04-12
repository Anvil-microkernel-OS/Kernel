use core::{cell::UnsafeCell, sync::atomic::{AtomicU32, AtomicU64, Ordering}};

use alloc::sync::Arc;
use spin::Mutex;
use x86_64::{VirtAddr};

use crate::{arch::amd64::{ipc::{cnode::CNode, message::{Capability, Rights}, object_table::{KernelObjType, KernelObject, ObjData, obj_insert, with_object}}, memory::{misc::phys_to_virt, vmm::{PAGE_SIZE, create_new_pt4_from_kernel_pt4}}, scheduler::{PerCpuSchedulerData, addr_space::AddrSpace, exec_loader::{phys_to_offset_page_table, user_task_trampoline}, stack::{DEFAULT_KERNEL_STACK_SIZE, allocate_kernel_stack}, syscall::{SyscallArguments, SyscallError, cap_check::{resolve_cap}}, task::{AtomicTaskState, Task, TaskId, TaskRegisters, TaskState, Tcb}, task_storage::{get_task_by_index, global_queue, table}}}, define_syscall_group};

define_syscall_group! {
    pub enum TcbSyscallNumbers {
        TcbCreate = 0x70,
        TcbResume = 0x71,
        TcbSetRegs = 0x72,
        TcbConfigure = 0x73,
    }
}

#[repr(C)]
pub struct GrRegs {
    rsp: u64,
    rip: u64,
    rdi: u64
}

fn tcb_set_regs(curr_task_id: u32, cap_tcb: u64) -> Result<u64, SyscallError> {
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

    let task = get_task_by_index(target_task_id_by_tcb).expect("Task Not found");
    
    let regs_addr = curr.tcb.ipc_buff_paddr.lock().expect("No buffer for syscalls provided!");

    let regs: GrRegs = unsafe {
        let virt = phys_to_virt(regs_addr);
        core::ptr::read(virt as *const GrRegs)
    };

    let stack_top_ptr = task.tcb.kernel_stack.top.as_u64() as *mut u64;

    unsafe {
        stack_top_ptr.sub(1).write(regs.rsp - 8);           
        stack_top_ptr.sub(2).write(regs.rip);           
        stack_top_ptr.sub(3).write(user_task_trampoline as u64);// ret
        for i in 4..=18 {
            stack_top_ptr.sub(i).write(0);
        }
        stack_top_ptr.sub(10).write(regs.rdi);            
    }

    let initial_rsp = unsafe { stack_top_ptr.sub(18) } as u64;

    unsafe { (*task.registers.get()).rsp = initial_rsp; }

    Ok(0)
}

//thread state check!!!
fn tcb_configure(curr_task_id: u32, cap_tcb: u64, cap_vspace: u64, ipc_buff_vaddr: VirtAddr, vmo_cap_idx: u64) -> Result<u64, SyscallError> {
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

    let (handle_vspace, _rights) = match resolve_cap(&curr, cap_vspace, KernelObjType::VSpace, Rights::ALL) {
        Ok(h) => h,
        Err(e) => return Err(e.to_syscall_error())
    };

    let target_task_id_by_vspace = match with_object(handle_vspace, |obj| {
        match &obj.data {
            ObjData::VSpace(task_id) => Some(*task_id),
            _ => None,
        }
    }).flatten() {
        Some(id) => id,
        None => return Err(SyscallError::InvalidArgument),
    };

    if target_task_id_by_tcb != target_task_id_by_vspace {
        return Err(SyscallError::InvalidArgument);
    }

    let target_task_id = target_task_id_by_tcb;

    if target_task_id == curr_task_id {
        return Err(SyscallError::PermissionDenied);
    }

    let task = get_task_by_index(target_task_id).expect("Task Not found");

    let (vmo_handle, _) = match resolve_cap(
        &curr, vmo_cap_idx, KernelObjType::Vmo, Rights::READ
    ) {
        Ok(h)  => h,
        Err(e) => return Err(e.to_syscall_error())
    }; 

    let (frames, vmo_size) = match with_object(vmo_handle, |obj| {
        match &obj.data {
            ObjData::Vmo(vmo) => Some((vmo.frames.clone(), vmo.size)),
            _                  => None,
        }
    }).flatten() {
        Some(v) => v,
        None    => return Err(SyscallError::NotFound),
    };

    if vmo_size != PAGE_SIZE {
        return Err(SyscallError::InvalidArgument);
    }

    task.tcb.ipc_buff_paddr.lock().replace(frames[0].as_u64() as usize);
    task.tcb.ipc_buff_vaddr.lock().replace(ipc_buff_vaddr);

    //todo - set fault handler

    Ok(0)
}

fn tcb_create() -> Result<u64, SyscallError> {
    static NEXT_ID: AtomicU32 = AtomicU32::new(2);
    let new_task_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

    let new_pml4_phys = create_new_pt4_from_kernel_pt4();
    let pt = phys_to_offset_page_table(new_pml4_phys);

    let task_def = Task {
        id: TaskId::new(new_task_id),
        registers: UnsafeCell::new(TaskRegisters::default()),
        tcb: Tcb {
            wake_at_tick:  Mutex::new(AtomicU64::new(0)),
            addr_space:    Mutex::new(AddrSpace::new(pt)),
            kernel_stack:  allocate_kernel_stack(DEFAULT_KERNEL_STACK_SIZE),
            cnode:         Mutex::new(CNode::new()), 
            task_state:    AtomicTaskState::new(TaskState::Configuring),
            ipc_buff_paddr: Mutex::new(None),
            ipc_buff_vaddr: Mutex::new(None),
        }
    };

    let task_arc = Arc::new(task_def);

    let handle_tcb = obj_insert(KernelObject::new(
        KernelObjType::Thread,
        ObjData::Thread(task_arc.id.id()),
    )).expect("Can not create handle");

    let cap_tcb = Capability::new(handle_tcb, Rights::ALL);

    let handle_vspace = obj_insert(KernelObject::new(
        KernelObjType::VSpace,
        ObjData::VSpace(task_arc.id.id()),
    )).expect("Can not create handle");

    let cap_vspace = Capability::new(handle_vspace, Rights::ALL);

    let handle_cnode = obj_insert(KernelObject::new(
        KernelObjType::CNode,
        ObjData::CNode(task_arc.id.id()),
    )).expect("Can not create handle");

    let cap_cnode = Capability::new(handle_cnode, Rights::ALL);

    let curr_task_id = PerCpuSchedulerData::get().curr_task_id.id();
    let curr = get_task_by_index(curr_task_id).unwrap();

    table().insert(task_arc);

        
    let slot_tcb = curr.tcb.cnode
        .lock()
        .alloc(cap_tcb).expect("Cnode is full") as u64;

    let slot_vspace = curr.tcb.cnode
        .lock()
        .alloc(cap_vspace).expect("Cnode is full") as u64;

    let slot_cnode = curr.tcb.cnode
        .lock()
        .alloc(cap_cnode).expect("Cnode is full") as u64;


    let ipc_addr = phys_to_virt(curr.tcb.ipc_buff_paddr.lock().expect("No ipc buff provided for syscall!"));

    unsafe {
        let ptr = ipc_addr as *mut u64;
        ptr.write(slot_tcb);
        ptr.add(1).write(slot_vspace);
        ptr.add(2).write(slot_cnode);
    }

    Ok(0)
}

fn tcb_resume(tcb_cap: u64) -> Result<u64, SyscallError> {
    let curr_task_id = PerCpuSchedulerData::get().curr_task_id.id();
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
        TcbSyscallNumbers::TcbConfigure => tcb_configure(curr_task_id, args.arg1, args.arg2, VirtAddr::new(args.arg3), args.arg4),
        TcbSyscallNumbers::TcbCreate => tcb_create(),
        TcbSyscallNumbers::TcbResume => tcb_resume(args.arg1),
        TcbSyscallNumbers::TcbSetRegs => tcb_set_regs(curr_task_id, args.arg1)
    }
}