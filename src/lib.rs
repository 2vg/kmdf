#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WDKAllocator;
#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WDKAllocator = WDKAllocator;

use core::{mem::zeroed, ptr::null_mut};
use spinning_top::Spinlock;
use wdk::println;
use wdk_sys::{
    ntddk::IoCreateDevice, ntddk::IoDeleteDevice, DRIVER_OBJECT, FILE_DEVICE_UNKNOWN, NTSTATUS,
    PCUNICODE_STRING, PDEVICE_OBJECT, STATUS_SUCCESS,
};
use winapi::{
    km::fwp::{
        fwpmk::{
            FWPM_ACTION0_u, FWPM_FILTER0_u, FwpmCalloutAdd0, FwpmCalloutDeleteById0,
            FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
            FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpsCalloutUnregisterById0, FWPM_ACTION0,
            FWPM_CALLOUT0, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_SUBLAYER0, RPC_C_AUTHN_WINNT,
        },
        fwpsk::{
            FwpsCalloutRegister1, FWPS_CALLOUT1, FWPS_CALLOUT_NOTIFY_TYPE, FWPS_CLASSIFY_OUT0,
            FWPS_FILTER1, FWPS_INCOMING_METADATA_VALUES0, FWPS_INCOMING_VALUES0,
            FWP_ACTION_CALLOUT_INSPECTION,
        },
        fwptypes::{FWP_VALUE0_u, FWP_BYTE_BLOB, FWP_EMPTY, FWP_VALUE0},
    },
    shared::{
        guiddef::GUID,
        ntdef::{PCVOID, PVOID},
        ws2def::IPPROTO_ICMP,
    },
    um::winnt::HANDLE,
};
use windows_sys::w;

const CALLOUT_OUT_GUID: GUID = GUID {
    Data1: 0xd147e90a,
    Data2: 0xa6d4,
    Data3: 0x4ec3,
    Data4: [0x82, 0xa9, 0xc1, 0x60, 0x32, 0x72, 0x9f, 0x44],
};

const SUBLAYER_GUID: GUID = GUID {
    Data1: 0xd55044d0,
    Data2: 0x110b,
    Data3: 0x4819,
    Data4: [0xbe, 0xfe, 0x2e, 0x52, 0x2c, 0x99, 0x09, 0x42],
};

const FILTER_GUID: GUID = GUID {
    Data1: 0x5951d0fe,
    Data2: 0x5218,
    Data3: 0x44e4,
    Data4: [0xa2, 0xd3, 0xb9, 0xbf, 0x43, 0xef, 0x8f, 0x4f],
};

// 0x5926dfc8_e3cf_4426_a283_dc393f5d0f9d
const FWPM_LAYER_INBOUND_TRANSPORT_V4: GUID = GUID {
    Data1: 0x5926dfc8,
    Data2: 0xe3cf,
    Data3: 0x4426,
    Data4: [0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d],
};

#[derive(Debug)]
#[repr(C)]
pub struct UnsafeSend<T>(pub T);

unsafe impl<T> Send for UnsafeSend<T> {}

#[derive(Debug)]
#[repr(C)]
pub struct GlobalVar {
    wfp_handle: HANDLE,
    device_object: PDEVICE_OBJECT,
    register_callout_id: u32,
    add_callout_id: u32,
    filter_callout_id: u64,
}

static GLOBAL: Spinlock<UnsafeSend<GlobalVar>> = Spinlock::new(UnsafeSend(GlobalVar {
    wfp_handle: null_mut(),
    device_object: null_mut(),
    register_callout_id: 0,
    add_callout_id: 0,
    filter_callout_id: 0,
}));

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    println!("Hello World !");

    driver.DriverUnload = Some(driver_exit);

    wfp_init(driver);

    return STATUS_SUCCESS;
}

unsafe extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {
    wfp_term(driver);
    println!("Good Bye World !");
}

unsafe extern "system" fn wfp_init(driver_object: &mut DRIVER_OBJECT) {
    let mut global = GLOBAL.lock();

    let nt_status = IoCreateDevice(
        driver_object,
        0,
        core::ptr::null_mut(),
        FILE_DEVICE_UNKNOWN,
        0,
        0,
        &mut global.0.device_object,
    );
    nt_status_check(nt_status, "IoCreateDevice");

    let nt_status = FwpmEngineOpen0(
        null_mut(),
        RPC_C_AUTHN_WINNT,
        null_mut(),
        null_mut(),
        &mut global.0.wfp_handle,
    );
    nt_status_check(nt_status, "FwpmEngineOpen0");

    let callout_register = FWPS_CALLOUT1 {
        calloutKey: CALLOUT_OUT_GUID,
        flags: 0,
        classifyFn: Some(callout_filter),
        notifyFn: Some(callout_notify),
        flowDeleteFn: None,
    };

    let nt_status = FwpsCalloutRegister1(
        global.0.device_object as _,
        &callout_register,
        &mut global.0.register_callout_id,
    );
    nt_status_check(nt_status, "FwpsCalloutRegister1");

    let callout_add = FWPM_CALLOUT0 {
        calloutKey: CALLOUT_OUT_GUID,
        flags: 0,
        displayData: FWPM_DISPLAY_DATA0 {
            name: w!("Test ICPM Filter"),
            description: w!("Test ICPM Filter Descripton."),
        },
        providerKey: 0 as _,
        providerData: FWP_BYTE_BLOB {
            size: 0,
            data: 0 as _,
        },
        applicableLayer: FWPM_LAYER_INBOUND_TRANSPORT_V4,
        calloutId: global.0.register_callout_id,
    };
    let nt_status = FwpmCalloutAdd0(
        global.0.wfp_handle,
        &callout_add,
        null_mut(),
        &mut global.0.add_callout_id,
    );
    nt_status_check(nt_status, "FwpmCalloutAdd0");

    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_GUID,
        displayData: FWPM_DISPLAY_DATA0 {
            name: w!("Test ICPM Filter Sublayer"),
            description: w!("Test ICPM Filter Sublayer Descripton."),
        },
        flags: 0,
        providerKey: 0 as _,
        providerData: FWP_BYTE_BLOB {
            size: 0,
            data: 0 as _,
        },
        weight: u16::MAX,
    };
    let nt_status = FwpmSubLayerAdd0(global.0.wfp_handle, &sublayer, null_mut());
    nt_status_check(nt_status, "FwpmSubLayerAdd0");

    let fwp_value_empty = zeroed::<FWP_VALUE0_u>();
    let fwp_filter = zeroed::<FWPM_FILTER0_u>();
    let mut fwp_action = zeroed::<FWPM_ACTION0_u>();

    *fwp_action.calloutKey_mut() = CALLOUT_OUT_GUID;

    let filter = FWPM_FILTER0 {
        filterKey: FILTER_GUID,
        displayData: FWPM_DISPLAY_DATA0 {
            name: w!("Test ICPM Filter"),
            description: w!("Test ICPM Filter Descripton."),
        },
        flags: 0,
        providerKey: 0 as _,
        providerData: FWP_BYTE_BLOB {
            size: 0,
            data: 0 as _,
        },
        layerKey: FWPM_LAYER_INBOUND_TRANSPORT_V4,
        subLayerKey: SUBLAYER_GUID,
        weight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            u: fwp_value_empty,
        },
        numFilterConditions: 0,
        filterCondition: 0 as _,
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_CALLOUT_INSPECTION,
            u: fwp_action,
        },
        u: fwp_filter,
        reserved: 0 as _,
        filterId: global.0.filter_callout_id,
        effectiveWeight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            u: fwp_value_empty,
        },
    };
    let nt_status = FwpmFilterAdd0(
        global.0.wfp_handle,
        &filter,
        null_mut(),
        &mut global.0.filter_callout_id,
    );
    nt_status_check(nt_status, "FwpmFilterAdd0");
}

unsafe extern "system" fn callout_filter(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
    in_meta_values: *const FWPS_INCOMING_METADATA_VALUES0,
    layer_data: PVOID,
    _classify_context: PCVOID,
    _filter: *const FWPS_FILTER1,
    _flow_context: u64,
    _classify_out: *mut FWPS_CLASSIFY_OUT0,
) {
    //    パケットが次の条件の時にのみPong！が出る
    // 1) layer_data     が存在する
    // 2) in_fixed_valuesが存在し、ICMPであること
    // 3) in_meta_values が存在し、IPヘッダーが正しい(サイズが0以下の場合、正しくない)

    if layer_data.is_null()
        || in_fixed_values.is_null()
        || (*in_fixed_values).incomingValue.is_null()
        || in_meta_values.is_null()
        || (*in_meta_values).ipHeaderSize <= 0
    {
        return;
    }

    // incomingValueのアドレスをずらすことで別のINCOMING_VALUEになる
    // ここで使用したい FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL は0と定義されているため、
    // ここでは正直ずらさなくても処理は出来る :D
    let incoming_offset = (*in_fixed_values).incomingValue.offset(0);
    if incoming_offset.is_null() {
        return;
    }

    let incoming_data = *incoming_offset;
    if *incoming_data.value.u.uint8() as u32 != IPPROTO_ICMP {
        return;
    }

    println!("Pong!");
}

extern "system" fn callout_notify(
    _notify_type: FWPS_CALLOUT_NOTIFY_TYPE,
    _filter_key: *const GUID,
    _filter: *const FWPS_FILTER1,
) -> NTSTATUS {
    return STATUS_SUCCESS;
}

unsafe extern "system" fn wfp_term(driver_object: *mut DRIVER_OBJECT) {
    let global = GLOBAL.lock();

    if !global.0.wfp_handle.is_null() {
        if global.0.filter_callout_id != 0 {
            println!("Deleting filter data...");
            let nt_status = FwpmFilterDeleteById0(global.0.wfp_handle, global.0.filter_callout_id);
            nt_status_check(nt_status, "FwpmFilterDeleteById0");

            println!("Deleting sublayer...");
            let nt_status = FwpmSubLayerDeleteByKey0(global.0.wfp_handle, &SUBLAYER_GUID);
            nt_status_check(nt_status, "FwpmSubLayerDeleteByKey0");
        }

        if global.0.add_callout_id != 0 {
            println!("Deleting callout data...");
            let nt_status = FwpmCalloutDeleteById0(global.0.wfp_handle, global.0.add_callout_id);
            nt_status_check(nt_status, "FwpmCalloutDeleteById0");
        }

        if global.0.register_callout_id != 0 {
            println!("Unregister callout ...");
            let nt_status = FwpsCalloutUnregisterById0(global.0.register_callout_id);
            nt_status_check(nt_status, "FwpsCalloutUnregisterById0");
        }

        let nt_status = FwpmEngineClose0(global.0.wfp_handle);
        nt_status_check(nt_status, "FwpmEngineClose0");
    }

    if !(*driver_object).DeviceObject.is_null() {
        IoDeleteDevice((*driver_object).DeviceObject);
        println!("Success: IoDeleteDevice successed.");
    }
}

extern "system" fn nt_status_check(code: i32, function_name: &'static str) {
    if code == STATUS_SUCCESS {
        println!("Success: {function_name} successed {code:#010X}");
    } else {
        println!("Error: {function_name} failed {code:#010X}");
    };
}
