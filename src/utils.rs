use nanos_sdk::bindings::os_serial;
use uuid::Uuid;

const LEDGER_SERIAL_SIZE: usize = 7;

pub fn device_serial() -> [u8; LEDGER_SERIAL_SIZE] {
    let mut serial = [0_u8; LEDGER_SERIAL_SIZE];

    unsafe {
        os_serial(serial.as_mut_ptr(), LEDGER_SERIAL_SIZE as u32);
    }

    serial
}

pub fn device_uuid() -> [u8; 16] {
    let serial = device_serial();
    let custom_namespace = Uuid::new_v5(&Uuid::NAMESPACE_DNS, b"ledger.fr");
    Uuid::new_v5(&custom_namespace, &serial).into_bytes()
}
