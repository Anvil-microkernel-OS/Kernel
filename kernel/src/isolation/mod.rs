use alloc::sync::Arc;
use spin::Once;

use crate::isolation::domain::Domain;

pub mod domain;

static ROOT_DOMAIN: Once<Arc<Domain>> = Once::new();


pub fn init_root_domain() {
    ROOT_DOMAIN.call_once(|| {
        Domain::new_root(0, "root")
    });
}

pub fn root_domain() -> &'static Arc<Domain> {
    ROOT_DOMAIN.get().expect("root domain not initialized")
}