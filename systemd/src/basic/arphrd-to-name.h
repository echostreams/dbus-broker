const char *arphrd_to_name(int id) {
        switch(id) {
        case ARPHRD_SIT: return "SIT";
        case ARPHRD_EUI64: return "EUI64";
        case ARPHRD_SKIP: return "SKIP";
        case ARPHRD_ASH: return "ASH";
        case ARPHRD_ATM: return "ATM";
        case ARPHRD_AX25: return "AX25";
        case ARPHRD_NETLINK: return "NETLINK";
        case ARPHRD_ADAPT: return "ADAPT";
        case ARPHRD_PPP: return "PPP";
        case ARPHRD_FCAL: return "FCAL";
        case ARPHRD_6LOWPAN: return "6LOWPAN";
        case ARPHRD_IEEE80211_PRISM: return "IEEE80211_PRISM";
        case ARPHRD_FCPL: return "FCPL";
        case ARPHRD_FCPP: return "FCPP";
        case ARPHRD_FCFABRIC: return "FCFABRIC";
        case ARPHRD_IEEE80211_RADIOTAP: return "IEEE80211_RADIOTAP";
        case ARPHRD_IP6GRE: return "IP6GRE";
        case ARPHRD_NETROM: return "NETROM";
        case ARPHRD_HIPPI: return "HIPPI";
        case ARPHRD_FRAD: return "FRAD";
        case ARPHRD_BIF: return "BIF";
        case ARPHRD_PHONET: return "PHONET";
        case ARPHRD_SLIP: return "SLIP";
        case ARPHRD_PHONET_PIPE: return "PHONET_PIPE";
        case ARPHRD_CSLIP: return "CSLIP";
        case ARPHRD_TUNNEL: return "TUNNEL";
        case ARPHRD_CHAOS: return "CHAOS";
        case ARPHRD_IEEE802: return "IEEE802";
        case ARPHRD_ETHER: return "ETHER";
        case ARPHRD_DDCMP: return "DDCMP";
        case ARPHRD_FDDI: return "FDDI";
        case ARPHRD_METRICOM: return "METRICOM";
        case ARPHRD_IPGRE: return "IPGRE";
        case ARPHRD_IEEE802_TR: return "IEEE802_TR";
        case ARPHRD_CAN: return "CAN";
        case ARPHRD_IEEE80211: return "IEEE80211";
        case ARPHRD_PRONET: return "PRONET";
        case ARPHRD_HWX25: return "HWX25";
        case ARPHRD_CAIF: return "CAIF";
        case ARPHRD_EETHER: return "EETHER";
        case ARPHRD_IPDDP: return "IPDDP";
        case ARPHRD_ECONET: return "ECONET";
        case ARPHRD_PIMREG: return "PIMREG";
        case ARPHRD_DLCI: return "DLCI";
        case ARPHRD_APPLETLK: return "APPLETLK";
        case ARPHRD_TUNNEL6: return "TUNNEL6";
        case ARPHRD_IEEE1394: return "IEEE1394";
        case ARPHRD_RAWHDLC: return "RAWHDLC";
        case ARPHRD_CISCO: return "CISCO";
        case ARPHRD_NONE: return "NONE";
        case ARPHRD_X25: return "X25";
        case ARPHRD_VOID: return "VOID";
        case ARPHRD_VSOCKMON: return "VSOCKMON";
        case ARPHRD_INFINIBAND: return "INFINIBAND";
        case ARPHRD_IRDA: return "IRDA";
        case ARPHRD_IEEE802154: return "IEEE802154";
        case ARPHRD_IEEE802154_MONITOR: return "IEEE802154_MONITOR";
        case ARPHRD_RAWIP: return "RAWIP";
        case ARPHRD_ROSE: return "ROSE";
        case ARPHRD_LAPB: return "LAPB";
        case ARPHRD_ARCNET: return "ARCNET";
        case ARPHRD_CSLIP6: return "CSLIP6";
        case ARPHRD_LOCALTLK: return "LOCALTLK";
        case ARPHRD_SLIP6: return "SLIP6";
        case ARPHRD_RSRVD: return "RSRVD";
        case ARPHRD_LOOPBACK: return "LOOPBACK";
        default: return NULL;
        }
}