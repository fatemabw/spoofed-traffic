module Spoofed;

export {
        redef enum Notice::Type += {
                ## A connection to the internal IPs was encountered
                spoofed_traffic_ns
        };
}

event new_connection(c: connection) &priority=-5
{
    if ( c$id$orig_h in Site::local_nets && c$id$resp_h in Site::local_nets )

         NOTICE([$note=spoofed_traffic_ns, $msg=fmt("An inter-vlan connection was seen."), $conn=c,
                 $identifier=cat(c$id$resp_h,c$id$orig_h)]);
}
