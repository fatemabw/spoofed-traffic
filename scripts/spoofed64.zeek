module Spoofed;

export {

        redef enum Notice::Type += {
                ## A connection to the intra vlan IPs was encountered
                intra_vlan_traffic
        };
        const dbfile = "vlan.txt" &redef;
}	

type Idx1: record {
        v4_network: subnet;
};

type Val1: record {
        Vlan: int;
        Location: string;
        v6_network: subnet;
};

type Idx2: record {
        v6_network: subnet;
};

type Val2: record {
        Vlan: int;
        Location: string;
        v4_network: subnet;
};

global VLAN4: table[subnet] of Val1 = table();
global VLAN6: table[subnet] of Val2 = table();

type vlanInfo: record {
        orig_vlan: int &optional;
        resp_vlan: int &optional;
};

redef record connection += {
        vlans: vlanInfo &optional;
};

event zeek_init()
{
    Input::add_table([$source=dbfile, $name="VLAN4",
                      $idx=Idx1, $val=Val1, $destination=VLAN4, $mode=Input::STREAM]);
    Input::remove("VLAN4");
    
    Input::add_table([$source=dbfile, $name="VLAN6",
                      $idx=Idx2, $val=Val2, $destination=VLAN6, $mode=Input::STREAM]);
    Input::remove("VLAN6");
}

event new_connection(c: connection) &priority=-5
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    if (!c?$vlans && is_v4_addr(src))
    {
        c$vlans=vlanInfo();
        
        if (dst in VLAN4)
        {
            c$vlans$resp_vlan = VLAN4[dst]$Vlan;
        }
        else
        {
            c$vlans$resp_vlan = 0;
        }
        if (src in VLAN4)
        {
            c$vlans$orig_vlan = VLAN4[src]$Vlan;
        }
        else
        {
            c$vlans$orig_vlan = 1;
        }
        if (c$vlans$resp_vlan == c$vlans$orig_vlan)
            NOTICE([$note=intra_vlan_traffic, $msg=fmt("A connection with intra-vlan traffic is seen."), $id=c$id, $conn=c]);
	}
    
    if (!c?$vlans && is_v6_addr(src))
    {
        c$vlans=vlanInfo();
        
        if (dst in VLAN6)
        {
            c$vlans$resp_vlan = VLAN6[dst]$Vlan;
        }
        else
        {
            c$vlans$resp_vlan = 0;
        }
        if (src in VLAN6)
        {
            c$vlans$orig_vlan = VLAN6[src]$Vlan;
        }
        else
        {
            c$vlans$orig_vlan = 1;
        }
        if (c$vlans$resp_vlan == c$vlans$orig_vlan)
            NOTICE([$note=intra_vlan_traffic, $msg=fmt("A connection with intra-vlan traffic is seen."), $id=c$id, $conn=c]);
	}
}
