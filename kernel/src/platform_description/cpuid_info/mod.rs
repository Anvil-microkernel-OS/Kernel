use raw_cpuid::CpuId;
use spin::Once;

#[inline]
fn vendor_as_str(vendor: &[u8; 12]) -> &str {
    str::from_utf8(vendor).unwrap_or("InvalidCPU")
}


pub struct CpuIdInfoFull {
    pub vendor: [u8; 12],
    pub has_sse: bool,
    pub has_sse2: bool,
    pub has_xsave: bool,
    pub has_avx: bool,
    pub has_nx: bool,
    pub has_apic: bool,
    pub has_x2apic: bool,
    pub logical_cores: u8,
    pub has_smap: bool,
    pub has_smep: bool,
}

static INFO: Once<CpuIdInfoFull> = Once::new();

fn init_cpuinfo() -> CpuIdInfoFull {
    let cpuid = CpuId::new();

    let vendor = if let Some(v) = cpuid.get_vendor_info() {
        let bytes = v.as_str().as_bytes();
        let mut buf = [0u8; 12];
        buf.copy_from_slice(&bytes[..12]);
        buf
    } else {
        *b"UnknownCPU  " 
    };

    let feature_info = cpuid.get_feature_info();
    let ext_features = cpuid.get_extended_processor_and_feature_identifiers();
    let ef_info = cpuid.get_extended_feature_info();

    CpuIdInfoFull {
        vendor,

        has_sse: feature_info
            .as_ref()
            .map(|f| f.has_sse())
            .unwrap_or(false),

        has_sse2: feature_info
            .as_ref()
            .map(|f| f.has_sse2())
            .unwrap_or(false),

        has_xsave: feature_info
            .as_ref()
            .map(|f| f.has_xsave())
            .unwrap_or(false),

        has_avx: feature_info
            .as_ref()
            .map(|f| f.has_avx())
            .unwrap_or(false),

        has_apic: feature_info
            .as_ref()
            .map(|f| f.has_apic())
            .unwrap_or(false),

        has_x2apic: feature_info
            .as_ref()
            .map(|f| f.has_x2apic())
            .unwrap_or(false),

        has_nx: ext_features
            .as_ref()
            .map(|f| f.has_execute_disable())
            .unwrap_or(false),

        logical_cores: feature_info
            .as_ref()
            .map(|f| f.max_logical_processor_ids())
            .unwrap_or(1),

        has_smap: ef_info.as_ref().map(|f| f.has_smap()).unwrap_or(false),
        has_smep: ef_info.as_ref().map(|f| f.has_smep()).unwrap_or(false),
    }
}

pub fn get_cpuid_full<'a>() -> &'a CpuIdInfoFull {
    INFO.call_once(|| {
        init_cpuinfo()
    });

    &INFO.get().unwrap()
}