use alloc::{sync::Arc, vec::Vec};
use spin::Once;

use crate::{arch::amd64::scheduler::task::Pid, isolation::domain::Domain};

pub mod domain;

static ROOT_DOMAIN: Once<Arc<Domain>> = Once::new();


pub fn init_root_domain(critical_procs: Option<Vec<Pid>>) {
    ROOT_DOMAIN.call_once(|| {
        Domain::new_root(0, "root", true, critical_procs)
    });
}

pub fn root_domain() -> &'static Arc<Domain> {
    ROOT_DOMAIN.get().expect("root domain not initialized")
}