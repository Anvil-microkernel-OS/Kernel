// syscall_groups.rs
#[macro_export]
macro_rules! define_syscall_group {
    (
        $vis:vis enum $name:ident {
            $($variant:ident = $value:expr),+ $(,)?
        }
    ) => {
        #[repr(u64)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis enum $name {
            $($variant = $value),+
        }

        impl From<$name> for u64 {
            fn from(val: $name) -> Self {
                val as u64
            }
        }

        impl TryFrom<u64> for $name {
            type Error = ();

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok($name::$variant),)+
                    _ => Err(()),
                }
            }
        }

        #[doc(hidden)]
        pub const _SYSCALL_GROUP: &[u64] = &[$($value),+];
    };
}

#[macro_export]
macro_rules! register_syscall_groups {
    ($($group:expr),+ $(,)?) => {
        const _: () = {
            const ALL_SYSCALLS: &[u64] = &{
                let mut all = [0u64; 0 $(+ $group.len())+];
                let mut idx = 0;
                $(
                    let mut i = 0;
                    while i < $group.len() {
                        all[idx] = $group[i];
                        idx += 1;
                        i += 1;
                    }
                )+
                all
            };

            const CHECK_DUPLICATES: () = {
                let mut i = 0;
                while i < ALL_SYSCALLS.len() {
                    let mut j = i + 1;
                    while j < ALL_SYSCALLS.len() {
                        if ALL_SYSCALLS[i] == ALL_SYSCALLS[j] {
                            panic!("Duplicate syscall number found across groups");
                        }
                        j += 1;
                    }
                    i += 1;
                }
            };
            let _ = CHECK_DUPLICATES;
        };
    };
}