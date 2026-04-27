@load frameworks/packet-filter/default
@load base/protocols/modbus

module ModbusMonitor;

export {
    redef enum Log::ID += { LOG_MODBUS_TRAFFIC };

    type ModbusTraffic: record {
        ts:        time    &log;
        uid:       string  &log;
        id:        conn_id &log;
        func:      count   &log;
        request:   bool    &log;
    };
}

redef Log::log_dir = ".";

event zeek_init()
    {
    Log::create_stream(
        LOG_MODBUS_TRAFFIC,
        [$columns = ModbusTraffic, $path = "modbus_traffic"]
    );
    }

hook Modbus::log_modbus(rec: Modbus::Info)
    {
    local r: ModbusTraffic = [$ts = rec$ts,
                              $uid = rec$uid,
                              $id = rec$id,
                              $func = rec$func,
                              $request = rec$is_orig];
    Log::write(LOG_MODBUS_TRAFFIC, r);
    }
