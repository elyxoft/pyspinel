#
#  Copyright (c) 2016-2017, The OpenThread Authors.
#  All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
""" Module-wide constants for spinel package. """


class SPINEL(object):
    """ Singular class that contains all Spinel constants. """
    HEADER_ASYNC = 0x80
    HEADER_DEFAULT = 0x81
    HEADER_EVENT_HANDLER = 0x82

    #=========================================
    # Spinel Commands: Host -> NCP
    #=========================================

    CMD_NOOP = 0
    CMD_RESET = 1
    CMD_PROP_VALUE_GET = 2
    CMD_PROP_VALUE_SET = 3
    CMD_PROP_VALUE_INSERT = 4
    CMD_PROP_VALUE_REMOVE = 5

    #=========================================
    # Spinel Command Responses: NCP -> Host
    #=========================================
    RSP_PROP_VALUE_IS = 6
    RSP_PROP_VALUE_INSERTED = 7
    RSP_PROP_VALUE_REMOVED = 8

    CMD_NET_SAVE = 9
    CMD_NET_CLEAR = 10
    CMD_NET_RECALL = 11

    RSP_HBO_OFFLOAD = 12
    RSP_HBO_RECLAIM = 13
    RSP_HBO_DROP = 14

    CMD_HBO_OFFLOADED = 15
    CMD_HBO_RECLAIMED = 16
    CMD_HBO_DROPPED = 17

    CMD_NEST__BEGIN = 15296
    CMD_NEST__END = 15360

    CMD_VENDOR__BEGIN = 15360
    CMD_VENDOR__END = 16384

    CMD_EXPERIMENTAL__BEGIN = 2000000
    CMD_EXPERIMENTAL__END = 2097152

    #=========================================
    # Spinel Properties
    #=========================================

    PROP_LAST_STATUS = 0  # < status [i]
    PROP_PROTOCOL_VERSION = 1  # < major, minor [i,i]
    PROP_NCP_VERSION = 2  # < version string [U]
    PROP_INTERFACE_TYPE = 3  # < [i]
    PROP_VENDOR_ID = 4  # < [i]
    PROP_CAPS = 5  # < capability list [A(i)]
    PROP_INTERFACE_COUNT = 6  # < Interface count [C]
    PROP_POWER_STATE = 7  # < PowerState [C]
    PROP_HWADDR = 8  # < PermEUI64 [E]
    PROP_LOCK = 9  # < PropLock [b]
    PROP_HBO_MEM_MAX = 10  # < Max offload mem [S]
    PROP_HBO_BLOCK_MAX = 11  # < Max offload block [S]
    PROP_HOST_POWER_STATE = 12
    PROP_MCU_POWER_STATE = 13

    PROP_BASE_EXT__BEGIN = 0x1000
    PROP_GPIO_CONFIG = PROP_BASE_EXT__BEGIN + 0
    PROP_GPIO_STATE = PROP_BASE_EXT__BEGIN + 2
    PROP_GPIO_STATE_SET = PROP_BASE_EXT__BEGIN + 3
    PROP_GPIO_STATE_CLEAR = PROP_BASE_EXT__BEGIN + 4
    PROP_TRNG_32 = PROP_BASE_EXT__BEGIN + 5
    PROP_TRNG_128 = PROP_BASE_EXT__BEGIN + 6
    PROP_TRNG_RAW_32 = PROP_BASE_EXT__BEGIN + 7
    PROP_UNSOL_UPDATE_FILTER = PROP_BASE_EXT__BEGIN + 8
    PROP_UNSOL_UPDATE_LIST = PROP_BASE_EXT__BEGIN + 9
    PROP_BASE_EXT__END = 0x1100

    PROP_PHY__BEGIN = 0x20
    PROP_PHY_ENABLED = PROP_PHY__BEGIN + 0  # < [b]
    PROP_PHY_CHAN = PROP_PHY__BEGIN + 1  # < [C]
    PROP_PHY_CHAN_SUPPORTED = PROP_PHY__BEGIN + 2  # < [A(C)]
    PROP_PHY_FREQ = PROP_PHY__BEGIN + 3  # < kHz [L]
    PROP_PHY_CCA_THRESHOLD = PROP_PHY__BEGIN + 4  # < dBm [c]
    PROP_PHY_TX_POWER = PROP_PHY__BEGIN + 5  # < [c]
    PROP_PHY_RSSI = PROP_PHY__BEGIN + 6  # < dBm [c]
    PROP_PHY_RX_SENSITIVITY = PROP_PHY__BEGIN + 7,  # < dBm [c]
    PROP_PHY_PCAP_ENABLED = PROP_PHY__BEGIN + 8,  # < [b]
    PROP_PHY_CHAN_PREFERRED = PROP_PHY__BEGIN + 9,  # < [A(C)]
    PROP_PHY_FEM_LNA_GAIN = PROP_PHY__BEGIN + 10, # < dBm [c]
    PROP_PHY_CHAN_MAX_POWER = PROP_PHY__BEGIN + 11
    PROP_PHY_REGION_CODE = PROP_PHY__BEGIN + 12
    PROP_PHY_CALIBRATED_POWER = PROP_PHY__BEGIN + 13
    PROP_PHY_CHAN_TARGET_POWER = PROP_PHY__BEGIN + 14
    PROP_PHY__END = 0x30

    PROP_PHY_EXT__BEGIN = 0x1200
    PROP_JAM_DETECT_ENABLE = PROP_PHY_EXT__BEGIN + 0
    PROP_JAM_DETECTED = PROP_PHY_EXT__BEGIN + 1
    PROP_JAM_DETECT_RSSI_THRESHOLD = PROP_PHY_EXT__BEGIN + 2
    PROP_JAM_DETECT_WINDOW = PROP_PHY_EXT__BEGIN + 3
    PROP_JAM_DETECT_BUSY = PROP_PHY_EXT__BEGIN + 4
    PROP_JAM_DETECT_HISTORY_BITMAP = PROP_PHY_EXT__BEGIN + 5
    PROP_CHANNEL_MONITOR_SAMPLE_INTERVAL = PROP_PHY_EXT__BEGIN + 6
    PROP_CHANNEL_MONITOR_RSSI_THRESHOLD = PROP_PHY_EXT__BEGIN + 7
    PROP_CHANNEL_MONITOR_SAMPLE_WINDOW = PROP_PHY_EXT__BEGIN + 8
    PROP_CHANNEL_MONITOR_SAMPLE_COUNT = PROP_PHY_EXT__BEGIN + 9
    PROP_CHANNEL_MONITOR_CHANNEL_OCCUPANCY = PROP_PHY_EXT__BEGIN + 10
    PROP_RADIO_CAPS = PROP_PHY_EXT__BEGIN + 11
    PROP_RADIO_COEX_METRICS = PROP_PHY_EXT__BEGIN + 12
    PROP_RADIO_COEX_ENABLE = PROP_PHY_EXT__BEGIN + 13
    PROP_PHY_EXT__END = 0x1300

    PROP_MAC__BEGIN = 0x30
    PROP_MAC_SCAN_STATE = PROP_MAC__BEGIN + 0  # < [C]
    PROP_MAC_SCAN_MASK = PROP_MAC__BEGIN + 1  # < [A(C)]
    PROP_MAC_SCAN_PERIOD = PROP_MAC__BEGIN + 2  # < ms-per-channel [S]
    # < chan,rssi,(laddr,saddr,panid,lqi),(proto,xtra) [Cct(ESSC)t(i)]
    PROP_MAC_SCAN_BEACON = PROP_MAC__BEGIN + 3
    PROP_MAC_15_4_LADDR = PROP_MAC__BEGIN + 4  # < [E]
    PROP_MAC_15_4_SADDR = PROP_MAC__BEGIN + 5  # < [S]
    PROP_MAC_15_4_PANID = PROP_MAC__BEGIN + 6  # < [S]
    PROP_MAC_RAW_STREAM_ENABLED = PROP_MAC__BEGIN + 7  # < [C]
    PROP_MAC_PROMISCUOUS_MODE = PROP_MAC__BEGIN + 8  # < [C]
    PROP_MAC_ENERGY_SCAN_RESULT = PROP_MAC__BEGIN + 9
    PROP_MAC_DATA_POLL_PERIOD = PROP_MAC__BEGIN + 10
    PROP_MAC_RX_ON_WHEN_IDLE_MODE = PROP_MAC__BEGIN + 11
    PROP_MAC__END = 0x40

    PROP_MAC_EXT__BEGIN = 0x1300
    # Format: `A(T(Ec))`
    # * `E`: EUI64 address of node
    # * `c`: Optional fixed RSSI. OT_MAC_FILTER_FIXED_RSS_OVERRIDE_DISABLED(127) means not set.
    PROP_MAC_ALLOWLIST = PROP_MAC_EXT__BEGIN + 0  # < [A(T(Ec))]
    PROP_MAC_ALLOWLIST_ENABLED = PROP_MAC_EXT__BEGIN + 1  # < [b]
    PROP_MAC_EXTENDED_ADDR = PROP_MAC_EXT__BEGIN + 2
    PROP_MAC_SRC_MATCH_ENABLED = PROP_MAC_EXT__BEGIN + 3  # < [b]
    PROP_MAC_SRC_MATCH_SHORT_ADDRESSES = PROP_MAC_EXT__BEGIN + 4  # < [A(S)]
    PROP_MAC_SRC_MATCH_EXTENDED_ADDRESSES = PROP_MAC_EXT__BEGIN + 5  # < [A(E)]

    # Format: `A(T(E))`
    # * `E`: EUI64 address of node
    PROP_MAC_DENYLIST = PROP_MAC_EXT__BEGIN + 6  # <[A(T(E))]
    PROP_MAC_DENYLIST_ENABLED = PROP_MAC_EXT__BEGIN + 7  # < [b]

    # Format: `A(T(Ec))`
    # * `E`: Optional EUI64 address of node. Set default RSS if not included.
    # * `c`: Fixed RSS. OT_MAC_FILTER_FIXED_RSS_OVERRIDE_DISABLED(127) means not set.
    PROP_MAC_FIXED_RSS = PROP_MAC_EXT__BEGIN + 8  # < [A(T(Ec))]

    # Format: `S`
    # * `S`: Current CCA (Clear Channel Assessment) failure rate.
    PROP_MAC_CCA_FAILURE_RATE = PROP_MAC_EXT__BEGIN + 9

    # Format: `C`
    # * `C`: The maximum (user-specified) number of direct frame transmission retries.
    PROP_MAC_MAX_RETRY_NUMBER_DIRECT = PROP_MAC_EXT__BEGIN + 10

    # Format: `C`
    # * `C`: The maximum (user-specified) number of indirect frame transmission retries.
    PROP_MAC_MAX_RETRY_NUMBER_INDIRECT = PROP_MAC_EXT__BEGIN + 11

    PROP_MAC_EXT__END = 0x1400

    PROP_NET__BEGIN = 0x40
    PROP_NET_SAVED = PROP_NET__BEGIN + 0  # < [b]
    PROP_NET_IF_UP = PROP_NET__BEGIN + 1  # < [b]
    PROP_NET_STACK_UP = PROP_NET__BEGIN + 2  # < [C]
    PROP_NET_ROLE = PROP_NET__BEGIN + 3  # < [C]
    PROP_NET_NETWORK_NAME = PROP_NET__BEGIN + 4  # < [U]
    PROP_NET_XPANID = PROP_NET__BEGIN + 5  # < [D]
    PROP_NET_NETWORK_KEY = PROP_NET__BEGIN + 6  # < [D]
    PROP_NET_KEY_SEQUENCE_COUNTER = PROP_NET__BEGIN + 7  # < [L]
    PROP_NET_PARTITION_ID = PROP_NET__BEGIN + 8  # < [L]
    PROP_NET_REQUIRE_JOIN_EXISTING = PROP_NET__BEGIN + 9
    PROP_NET_KEY_SWITCH_GUARDTIME = PROP_NET__BEGIN + 10  # < [L]
    PROP_NET_PSKC = PROP_NET__BEGIN + 11
    PROP_NET__END = 0x50

    PROP_THREAD__BEGIN = 0x50
    PROP_THREAD_LEADER_ADDR = PROP_THREAD__BEGIN + 0  # < [6]
    PROP_THREAD_PARENT = PROP_THREAD__BEGIN + 1  # < LADDR, SADDR [ES]
    PROP_THREAD_CHILD_TABLE = PROP_THREAD__BEGIN + 2  # < [A(t(ES))]
    PROP_THREAD_LEADER_RID = PROP_THREAD__BEGIN + 3  # < [C]
    PROP_THREAD_LEADER_WEIGHT = PROP_THREAD__BEGIN + 4  # < [C]
    PROP_THREAD_LOCAL_LEADER_WEIGHT = PROP_THREAD__BEGIN + 5  # < [C]
    PROP_THREAD_NETWORK_DATA = PROP_THREAD__BEGIN + 6  # < [D]
    PROP_THREAD_NETWORK_DATA_VERSION = PROP_THREAD__BEGIN + 7  # < [S]
    PROP_THREAD_STABLE_NETWORK_DATA = PROP_THREAD__BEGIN + 8  # < [D]
    PROP_THREAD_STABLE_NETWORK_DATA_VERSION = PROP_THREAD__BEGIN + 9  # < [S]
    # < array(ipv6prefix,prefixlen,stable,flags) [A(t(6CbC))]
    PROP_THREAD_ON_MESH_NETS = PROP_THREAD__BEGIN + 10
    # < array(ipv6prefix,prefixlen,stable,flags) [A(t(6CbC))]
    PROP_THREAD_OFF_MESH_ROUTES = PROP_THREAD__BEGIN + 11
    PROP_THREAD_ASSISTING_PORTS = PROP_THREAD__BEGIN + 12  # < array(portn) [A(S)]
    PROP_THREAD_ALLOW_LOCAL_NET_DATA_CHANGE = PROP_THREAD__BEGIN + 13  # < [b]
    PROP_THREAD_MODE = PROP_THREAD__BEGIN + 14
    PROP_THREAD__END = 0x60

    PROP_THREAD_EXT__BEGIN = 0x1500
    PROP_THREAD_CHILD_TIMEOUT = PROP_THREAD_EXT__BEGIN + 0  # < [L]
    PROP_THREAD_RLOC16 = PROP_THREAD_EXT__BEGIN + 1  # < [S]
    PROP_THREAD_ROUTER_UPGRADE_THRESHOLD = PROP_THREAD_EXT__BEGIN + 2  # < [C]
    PROP_THREAD_CONTEXT_REUSE_DELAY = PROP_THREAD_EXT__BEGIN + 3  # < [L]
    PROP_THREAD_NETWORK_ID_TIMEOUT = PROP_THREAD_EXT__BEGIN + 4  # < [b]
    PROP_THREAD_ACTIVE_ROUTER_IDS = PROP_THREAD_EXT__BEGIN + 5  # < [A(b)]
    PROP_THREAD_RLOC16_DEBUG_PASSTHRU = PROP_THREAD_EXT__BEGIN + 6  # < [b]
    PROP_THREAD_ROUTER_ROLE_ENABLED = PROP_THREAD_EXT__BEGIN + 7  # < [b]
    PROP_THREAD_ROUTER_DOWNGRADE_THRESHOLD = PROP_THREAD_EXT__BEGIN + 8  # < [C]
    PROP_THREAD_ROUTER_SELECTION_JITTER = PROP_THREAD_EXT__BEGIN + 9  # < [C]
    PROP_THREAD_PREFERRED_ROUTER_ID = PROP_THREAD_EXT__BEGIN + 10  # < [C]
    PROP_THREAD_NEIGHBOR_TABLE = PROP_THREAD_EXT__BEGIN + 11  # < [A(t(ESLCcCbLL))]
    PROP_THREAD_CHILD_COUNT_MAX = PROP_THREAD_EXT__BEGIN + 12  # < [C]
    PROP_THREAD_LEADER_NETWORK_DATA = PROP_THREAD_EXT__BEGIN + 13
    PROP_THREAD_STABLE_LEADER_NETWORK_DATA = PROP_THREAD_EXT__BEGIN + 14
    PROP_THREAD_JOINERS = PROP_THREAD_EXT__BEGIN + 15
    PROP_THREAD_COMMISSIONER_ENABLED = PROP_THREAD_EXT__BEGIN + 16
    PROP_THREAD_TMF_PROXY_ENABLED = PROP_THREAD_EXT__BEGIN + 17
    PROP_THREAD_TMF_PROXY_STREAM = PROP_THREAD_EXT__BEGIN + 18
    PROP_THREAD_DISCOVERY_SCAN_JOINER_FLAG = PROP_THREAD_EXT__BEGIN + 19
    PROP_THREAD_DISCOVERY_SCAN_ENABLE_FILTERING = PROP_THREAD_EXT__BEGIN + 20
    PROP_THREAD_DISCOVERY_SCAN_PANID = PROP_THREAD_EXT__BEGIN + 21
    PROP_THREAD_STEERING_DATA = PROP_THREAD_EXT__BEGIN + 22
    PROP_THREAD_ROUTER_TABLE = PROP_THREAD_EXT__BEGIN + 23
    PROP_THREAD_ACTIVE_DATASET = PROP_THREAD_EXT__BEGIN + 24
    PROP_THREAD_PENDING_DATASET = PROP_THREAD_EXT__BEGIN + 25
    PROP_THREAD_MGMT_SET_ACTIVE_DATASET = PROP_THREAD_EXT__BEGIN + 26
    PROP_THREAD_MGMT_SET_PENDING_DATASET = PROP_THREAD_EXT__BEGIN + 27
    PROP_DATASET_ACTIVE_TIMESTAMP = PROP_THREAD_EXT__BEGIN + 28
    PROP_DATASET_PENDING_TIMESTAMP = PROP_THREAD_EXT__BEGIN + 29
    PROP_DATASET_DELAY_TIMER = PROP_THREAD_EXT__BEGIN + 30
    PROP_DATASET_SECURITY_POLICY = PROP_THREAD_EXT__BEGIN + 31
    PROP_DATASET_RAW_TLVS = PROP_THREAD_EXT__BEGIN + 32
    PROP_THREAD_CHILD_TABLE_ADDRESSES = PROP_THREAD_EXT__BEGIN + 33
    PROP_THREAD_NEIGHBOR_TABLE_ERROR_RATES = PROP_THREAD_EXT__BEGIN + 34
    PROP_THREAD_ADDRESS_CACHE_TABLE = PROP_THREAD_EXT__BEGIN + 35
    PROP_THREAD_UDP_FORWARD_STREAM = PROP_THREAD_EXT__BEGIN + 36
    PROP_THREAD_MGMT_GET_ACTIVE_DATASET = PROP_THREAD_EXT__BEGIN + 37
    PROP_THREAD_MGMT_GET_PENDING_DATASET = PROP_THREAD_EXT__BEGIN + 38
    PROP_DATASET_DEST_ADDRESS = PROP_THREAD_EXT__BEGIN + 39
    PROP_THREAD_NEW_DATASET = PROP_THREAD_EXT__BEGIN + 40
    PROP_THREAD_CSL_PERIOD = PROP_THREAD_EXT__BEGIN + 41
    PROP_THREAD_CSL_TIMEOUT = PROP_THREAD_EXT__BEGIN + 42
    PROP_THREAD_CSL_CHANNEL = PROP_THREAD_EXT__BEGIN + 43
    PROP_THREAD_DOMAIN_NAME = PROP_THREAD_EXT__BEGIN + 44
    PROP_THREAD_LINK_METRICS_QUERY = PROP_THREAD_EXT__BEGIN + 45
    PROP_THREAD_LINK_METRICS_QUERY_RESULT = PROP_THREAD_EXT__BEGIN + 46
    PROP_THREAD_LINK_METRICS_PROBE = PROP_THREAD_EXT__BEGIN + 47
    PROP_THREAD_LINK_METRICS_MGMT_ENH_ACK = PROP_THREAD_EXT__BEGIN + 48
    PROP_THREAD_LINK_METRICS_MGMT_ENH_ACK_IE = PROP_THREAD_EXT__BEGIN + 49
    PROP_THREAD_LINK_METRICS_MGMT_FORWARD = PROP_THREAD_EXT__BEGIN + 50
    PROP_THREAD_LINK_METRICS_MGMT_RESPONSE = PROP_THREAD_EXT__BEGIN + 51
    PROP_THREAD_MLR_REQUEST = PROP_THREAD_EXT__BEGIN + 52
    PROP_THREAD_MLR_RESPONSE = PROP_THREAD_EXT__BEGIN + 53
    PROP_THREAD_DUA_ID = PROP_THREAD_EXT__BEGIN + 54
    PROP_THREAD_BACKBONE_ROUTER_PRIMARY = PROP_THREAD_EXT__BEGIN + 55
    PROP_THREAD_BACKBONE_ROUTER_LOCAL_STATE = PROP_THREAD_EXT__BEGIN + 56
    PROP_THREAD_BACKBONE_ROUTER_LOCAL_CONFIG = PROP_THREAD_EXT__BEGIN + 57
    PROP_THREAD_BACKBONE_ROUTER_LOCAL_REGISTER = PROP_THREAD_EXT__BEGIN + 58
    PROP_THREAD_BACKBONE_ROUTER_LOCAL_REGISTRATION_JITTER = PROP_THREAD_EXT__BEGIN + 59
    PROP_THREAD_EXT__END = 0x1600

    PROP_IPV6__BEGIN = 0x60
    PROP_IPV6_LL_ADDR = PROP_IPV6__BEGIN + 0  # < [6]
    PROP_IPV6_ML_ADDR = PROP_IPV6__BEGIN + 1  # < [6C]
    PROP_IPV6_ML_PREFIX = PROP_IPV6__BEGIN + 2  # < [6C]
    # < array(ipv6addr,prefixlen,valid,preferred,flags) [A(t(6CLLC))]
    PROP_IPV6_ADDRESS_TABLE = PROP_IPV6__BEGIN + 3
    # < array(ipv6prefix,prefixlen,iface,flags) [A(t(6CCC))]
    PROP_IPV6_ROUTE_TABLE = PROP_IPV6__BEGIN + 4
    PROP_IPv6_ICMP_PING_OFFLOAD = PROP_IPV6__BEGIN + 5  # < [b]
    PROP_IPV6_MULTICAST_ADDRESS_TABLE = PROP_IPV6__BEGIN + 6
    PROP_IPV6_ICMP_PING_OFFLOAD_MODE = PROP_IPV6__BEGIN + 7 # < [b]
    PROP_IPV6__END = 0x70

    PROP_STREAM__BEGIN = 0x70
    PROP_STREAM_DEBUG = PROP_STREAM__BEGIN + 0  # < [U]
    PROP_STREAM_RAW = PROP_STREAM__BEGIN + 1  # < [D]
    PROP_STREAM_NET = PROP_STREAM__BEGIN + 2  # < [D]
    PROP_STREAM_NET_INSECURE = PROP_STREAM__BEGIN + 3  # < [D]
    PROP_STREAM_LOG = PROP_STREAM__BEGIN + 4  # < [UD]
    PROP_STREAM__END = 0x80

    PROP_MESHCOP__BEGIN = 0x80
    PROP_MESHCOP_JOINER_STATE = PROP_MESHCOP__BEGIN + 0 # <[C]
    PROP_MESHCOP_JOINER_COMMISSIONING = PROP_MESHCOP__BEGIN + 1
    PROP_MESHCOP_COMMISSIONER_STATE = PROP_MESHCOP__BEGIN + 2
    PROP_MESHCOP_COMMISSIONER_JOINERS = PROP_MESHCOP__BEGIN + 3
    PROP_MESHCOP_COMMISSIONER_PROVISIONING_URL = PROP_MESHCOP__BEGIN + 4
    PROP_MESHCOP_COMMISSIONER_SESSION_ID = PROP_MESHCOP__BEGIN + 5
    PROP_MESHCOP_JOINER_DISCERNER = PROP_MESHCOP__BEGIN + 6
    PROP_MESHCOP__END = 0x90

    PROP_MESHCOP_EXT__BEGIN = 0x1800
    PROP_MESHCOP_COMMISSIONER_ANNOUNCE_BEGIN = PROP_MESHCOP_EXT__BEGIN + 0
    PROP_MESHCOP_COMMISSIONER_ENERGY_SCAN = PROP_MESHCOP_EXT__BEGIN + 1
    PROP_MESHCOP_COMMISSIONER_ENERGY_SCAN_RESULT = PROP_MESHCOP_EXT__BEGIN + 2
    PROP_MESHCOP_COMMISSIONER_PAN_ID_QUERY = PROP_MESHCOP_EXT__BEGIN + 3
    PROP_MESHCOP_COMMISSIONER_PAN_ID_CONFLICT_RESULT = PROP_MESHCOP_EXT__BEGIN + 4
    PROP_MESHCOP_COMMISSIONER_MGMT_GET = PROP_MESHCOP_EXT__BEGIN + 5
    PROP_MESHCOP_COMMISSIONER_MGMT_SET = PROP_MESHCOP_EXT__BEGIN + 6
    PROP_MESHCOP_COMMISSIONER_GENERATE_PSKC = PROP_MESHCOP_EXT__BEGIN + 7
    PROP_MESHCOP_EXT__END = 0x1900

    PROP_OPENTHREAD__BEGIN = 0x1900
    PROP_CHANNEL_MANAGER_NEW_CHANNEL = PROP_OPENTHREAD__BEGIN + 0
    PROP_CHANNEL_MANAGER_DELAY = PROP_OPENTHREAD__BEGIN + 1
    PROP_CHANNEL_MANAGER_SUPPORTED_CHANNELS = PROP_OPENTHREAD__BEGIN + 2
    PROP_CHANNEL_MANAGER_FAVORED_CHANNELS = PROP_OPENTHREAD__BEGIN + 3
    PROP_CHANNEL_MANAGER_CHANNEL_SELECT = PROP_OPENTHREAD__BEGIN + 4
    PROP_CHANNEL_MANAGER_AUTO_SELECT_ENABLED = PROP_OPENTHREAD__BEGIN + 5
    PROP_CHANNEL_MANAGER_AUTO_SELECT_INTERVAL = PROP_OPENTHREAD__BEGIN + 6
    PROP_THREAD_NETWORK_TIME = PROP_OPENTHREAD__BEGIN + 7
    PROP_TIME_SYNC_PERIOD = PROP_OPENTHREAD__BEGIN + 8
    PROP_TIME_SYNC_XTAL_THRESHOLD = PROP_OPENTHREAD__BEGIN + 9
    PROP_CHILD_SUPERVISION_INTERVAL = PROP_OPENTHREAD__BEGIN + 10
    PROP_CHILD_SUPERVISION_CHECK_TIMEOUT = PROP_OPENTHREAD__BEGIN + 11
    PROP_RCP_VERSION = PROP_OPENTHREAD__BEGIN + 12
    PROP_PARENT_RESPONSE_INFO = PROP_OPENTHREAD__BEGIN + 13
    PROP_SLAAC_ENABLED = PROP_OPENTHREAD__BEGIN + 14
    PROP_SUPPORTED_RADIO_LINKS = PROP_OPENTHREAD__BEGIN + 15
    PROP_NEIGHBOR_TABLE_MULTI_RADIO_INFO = PROP_OPENTHREAD__BEGIN + 16
    PROP_SRP_CLIENT_START = PROP_OPENTHREAD__BEGIN + 17
    PROP_SRP_CLIENT_LEASE_INTERVAL = PROP_OPENTHREAD__BEGIN + 18
    PROP_SRP_CLIENT_KEY_LEASE_INTERVAL = PROP_OPENTHREAD__BEGIN + 19
    PROP_SRP_CLIENT_HOST_INFO = PROP_OPENTHREAD__BEGIN + 20
    PROP_SRP_CLIENT_HOST_NAME = PROP_OPENTHREAD__BEGIN + 21
    PROP_SRP_CLIENT_HOST_ADDRESSES = PROP_OPENTHREAD__BEGIN + 22
    PROP_SRP_CLIENT_SERVICES = PROP_OPENTHREAD__BEGIN + 23
    PROP_SRP_CLIENT_HOST_SERVICES_REMOVE = PROP_OPENTHREAD__BEGIN + 24
    PROP_SRP_CLIENT_HOST_SERVICES_CLEAR = PROP_OPENTHREAD__BEGIN + 25
    PROP_SRP_CLIENT_EVENT = PROP_OPENTHREAD__BEGIN + 26
    PROP_SRP_CLIENT_SERVICE_KEY_ENABLED = PROP_OPENTHREAD__BEGIN + 27
    PROP_OPENTHREAD__END = 0x2000

    PROP_SERVER__BEGIN = 0xA0
    PROP_SERVER_ALLOW_LOCAL_DATA_CHANGE = PROP_SERVER__BEGIN + 0
    PROP_SERVER_SERVICES = PROP_SERVER__BEGIN + 1
    PROP_SERVER_LEADER_SERVICES = PROP_SERVER__BEGIN + 2
    PROP_SERVER__END = 0xB0

    PROP_RCP__BEGIN = 0xB0
    PROP_RCP_API_VERSION = PROP_RCP__BEGIN + 0,
    PROP_RCP_MIN_HOST_API_VERSION = PROP_RCP__BEGIN + 1
    PROP_RCP_LOG_CRASH_DUMP = PROP_RCP__BEGIN + 2
    PROP_RCP__END = 0xFF

    PROP_INTERFACE__BEGIN = 0x100
    # UART Bitrate
    # Format: `L`
    PROP_UART_BITRATE = PROP_INTERFACE__BEGIN + 0

    # UART Software Flow Control
    # Format: `b`
    PROP_UART_XON_XOFF = PROP_INTERFACE__BEGIN + 1
    PROP_INTERFACE__END = 0x200

    PROP_PIB_15_4__BEGIN = 0x400
    PROP_PIB_15_4_PHY_CHANNELS_SUPPORTED = PROP_PIB_15_4__BEGIN + 0x01  # < [A(L)]
    PROP_PIB_15_4_MAC_PROMISCUOUS_MODE = PROP_PIB_15_4__BEGIN + 0x51  # < [b]
    PROP_PIB_15_4_MAC_SECURITY_ENABLED = PROP_PIB_15_4__BEGIN + 0x5d  # < [b]
    PROP_PIB_15_4__END = 0x500

    PROP_CNTR__BEGIN = 0x500

    # Counter reset behavior
    # Format: `C`
    PROP_CNTR_RESET = PROP_CNTR__BEGIN + 0

    # The total number of transmissions.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_TOTAL = PROP_CNTR__BEGIN + 1

    # The number of transmissions with ack request.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_ACK_REQ = PROP_CNTR__BEGIN + 2

    # The number of transmissions that were acked.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_ACKED = PROP_CNTR__BEGIN + 3

    # The number of transmissions without ack request.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_NO_ACK_REQ = PROP_CNTR__BEGIN + 4

    # The number of transmitted data.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_DATA = PROP_CNTR__BEGIN + 5

    # The number of transmitted data poll.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_DATA_POLL = PROP_CNTR__BEGIN + 6

    # The number of transmitted beacon.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_BEACON = PROP_CNTR__BEGIN + 7

    # The number of transmitted beacon request.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_BEACON_REQ = PROP_CNTR__BEGIN + 8

    # The number of transmitted other types of frames.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_OTHER = PROP_CNTR__BEGIN + 9

    # The number of retransmission times.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_RETRY = PROP_CNTR__BEGIN + 10

    # The number of CCA failure times.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_ERR_CCA = PROP_CNTR__BEGIN + 11

    # The number of unicast packets transmitted.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_UNICAST = PROP_CNTR__BEGIN + 12

    # The number of broadcast packets transmitted.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_PKT_BROADCAST = PROP_CNTR__BEGIN + 13

    # The number of frame transmission failures due to abort error.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_ERR_ABORT = PROP_CNTR__BEGIN + 14

    # The total number of received packets.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_TOTAL = PROP_CNTR__BEGIN + 100

    # The number of received data.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_DATA = PROP_CNTR__BEGIN + 101

    # The number of received data poll.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_DATA_POLL = PROP_CNTR__BEGIN + 102

    # The number of received beacon.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_BEACON = PROP_CNTR__BEGIN + 103

    # The number of received beacon request.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_BEACON_REQ = PROP_CNTR__BEGIN + 104

    # The number of received other types of frames.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_OTHER = PROP_CNTR__BEGIN + 105

    # The number of received packets filtered by allowlist.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_FILT_WL = PROP_CNTR__BEGIN + 106

    # The number of received packets filtered by destination check.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_FILT_DA = PROP_CNTR__BEGIN + 107

    # The number of received packets that are empty.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_EMPTY = PROP_CNTR__BEGIN + 108

    # The number of received packets from an unknown neighbor.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_UKWN_NBR = PROP_CNTR__BEGIN + 109

    # The number of received packets whose source address is invalid.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_NVLD_SADDR = PROP_CNTR__BEGIN + 110

    # The number of received packets with a security error.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_SECURITY = PROP_CNTR__BEGIN + 111

    # The number of received packets with a checksum error.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_BAD_FCS = PROP_CNTR__BEGIN + 112

    # The number of received packets with other errors.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR_OTHER = PROP_CNTR__BEGIN + 113

    # The number of received duplicated.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_DUP = PROP_CNTR__BEGIN + 114

    # The number of unicast packets received.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_UNICAST = PROP_CNTR__BEGIN + 115

    # The number of broadcast packets received.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_PKT_BROADCAST = PROP_CNTR__BEGIN + 116

    # The total number of secure transmitted IP messages.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_IP_SEC_TOTAL = PROP_CNTR__BEGIN + 200

    # The total number of insecure transmitted IP messages.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_IP_INSEC_TOTAL = PROP_CNTR__BEGIN + 201

    # The number of dropped (not transmitted) IP messages.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_IP_DROPPED = PROP_CNTR__BEGIN + 202

    # The total number of secure received IP message.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_IP_SEC_TOTAL = PROP_CNTR__BEGIN + 203

    # The total number of insecure received IP message.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_IP_INSEC_TOTAL = PROP_CNTR__BEGIN + 204

    # The number of dropped received IP messages.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_IP_DROPPED = PROP_CNTR__BEGIN + 205

    # The number of transmitted spinel frames.
    # Format: `L` (Read-only) */
    PROP_CNTR_TX_TOTAL = PROP_CNTR__BEGIN + 300

    # The number of received spinel frames.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_TOTAL = PROP_CNTR__BEGIN + 301

    # The number of received spinel frames with error.
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_ERR = PROP_CNTR__BEGIN + 302

    # Number of out of order received spinel frames (tid increase by more than 1).
    # Format: `L` (Read-only) */
    PROP_CNTR_RX_OUT_OF_ORDER_TID = PROP_CNTR__BEGIN + 303

    # The number of successful Tx IP packets
    # Format: `L` (Read-only) */
    PROP_CNTR_IP_TX_SUCCESS = PROP_CNTR__BEGIN + 304

    # The number of successful Rx IP packets
    # Format: `L` (Read-only) */
    PROP_CNTR_IP_RX_SUCCESS = PROP_CNTR__BEGIN + 305

    # The number of failed Tx IP packets
    # Format: `L` (Read-only) */
    PROP_CNTR_IP_TX_FAILURE = PROP_CNTR__BEGIN + 306

    # The number of failed Rx IP packets
    # Format: `L` (Read-only) */
    PROP_CNTR_IP_RX_FAILURE = PROP_CNTR__BEGIN + 307

    # The message buffer counter info
    # Format: `SSSSSSSSSSSSSSSS` (Read-only)
    #     `S`, (TotalBuffers)           The number of buffers in the pool.
    #     `S`, (FreeBuffers)            The number of free message buffers.
    #     `S`, (6loSendMessages)        The number of messages in the 6lo send queue.
    #     `S`, (6loSendBuffers)         The number of buffers in the 6lo send queue.
    #     `S`, (6loReassemblyMessages)  The number of messages in the 6LoWPAN reassembly queue.
    #     `S`, (6loReassemblyBuffers)   The number of buffers in the 6LoWPAN reassembly queue.
    #     `S`, (Ip6Messages)            The number of messages in the IPv6 send queue.
    #     `S`, (Ip6Buffers)             The number of buffers in the IPv6 send queue.
    #     `S`, (MplMessages)            The number of messages in the MPL send queue.
    #     `S`, (MplBuffers)             The number of buffers in the MPL send queue.
    #     `S`, (MleMessages)            The number of messages in the MLE send queue.
    #     `S`, (MleBuffers)             The number of buffers in the MLE send queue.
    #     `S`, (ArpMessages)            The number of messages in the ARP send queue.
    #     `S`, (ArpBuffers)             The number of buffers in the ARP send queue.
    #     `S`, (CoapClientMessages)     The number of messages in the CoAP client send queue.
    #     `S`  (CoapClientBuffers)      The number of buffers in the CoAP client send queue.
    PROP_MSG_BUFFER_COUNTERS = PROP_CNTR__BEGIN + 400

    # All MAC related counters.
    # Format: t(A(L))t(A(L))  (Read-only)
    #
    # The transmit structure includes:
    #
    #     'L': TxTotal              (The total number of transmissions).
    #     'L': TxUnicast            (The total number of unicast transmissions).
    #     'L': TxBroadcast          (The total number of broadcast transmissions).
    #     'L': TxAckRequested       (The number of transmissions with ack request).
    #     'L': TxAcked              (The number of transmissions that were acked).
    #     'L': TxNoAckRequested     (The number of transmissions without ack request).
    #     'L': TxData               (The number of transmitted data).
    #     'L': TxDataPoll           (The number of transmitted data poll).
    #     'L': TxBeacon             (The number of transmitted beacon).
    #     'L': TxBeaconRequest      (The number of transmitted beacon request).
    #     'L': TxOther              (The number of transmitted other types of frames).
    #     'L': TxRetry              (The number of retransmission times).
    #     'L': TxErrCca             (The number of CCA failure times).
    #     'L': TxErrAbort           (The number of frame transmission failures due to abort error).
    #     'L': TxErrBusyChannel     (The number of frames that were dropped due to a busy channel).
    #
    # The receive structure includes:
    #
    #     'L': RxTotal              (The total number of received packets).
    #     'L': RxUnicast            (The total number of unicast packets received).
    #     'L': RxBroadcast          (The total number of broadcast packets received).
    #     'L': RxData               (The number of received data).
    #     'L': RxDataPoll           (The number of received data poll).
    #     'L': RxBeacon             (The number of received beacon).
    #     'L': RxBeaconRequest      (The number of received beacon request).
    #     'L': RxOther              (The number of received other types of frames).
    #     'L': RxAddressFiltered    (The number of received packets filtered by address filter (allowlist or denylist)).
    #     'L': RxDestAddrFiltered   (The number of received packets filtered by destination check).
    #     'L': RxDuplicated         (The number of received duplicated packets).
    #     'L': RxErrNoFrame         (The number of received packets with no or malformed content).
    #     'L': RxErrUnknownNeighbor (The number of received packets from unknown neighbor).
    #     'L': RxErrInvalidSrcAddr  (The number of received packets whose source address is invalid).
    #     'L': RxErrSec             (The number of received packets with security error).
    #     'L': RxErrFcs             (The number of received packets with FCS error).
    #     'L': RxErrOther           (The number of received packets with other error).
    PROP_CNTR_ALL_MAC_COUNTERS = PROP_CNTR__BEGIN + 401

    # Thread MLE counters.
    # Format: `SSSSSSSSS`  (Read-only)
    #    'S': DisabledRole                  (The number of times device entered OT_DEVICE_ROLE_DISABLED role).
    #    'S': DetachedRole                  (The number of times device entered OT_DEVICE_ROLE_DETACHED role).
    #    'S': ChildRole                     (The number of times device entered OT_DEVICE_ROLE_CHILD role).
    #    'S': RouterRole                    (The number of times device entered OT_DEVICE_ROLE_ROUTER role).
    #    'S': LeaderRole                    (The number of times device entered OT_DEVICE_ROLE_LEADER role).
    #    'S': AttachAttempts                (The number of attach attempts while device was detached).
    #    'S': PartitionIdChanges            (The number of changes to partition ID).
    #    'S': BetterPartitionAttachAttempts (The number of attempts to attach to a better partition).
    #    'S': ParentChanges                 (The number of times device changed its parents).
    PROP_CNTR_MLE_COUNTERS = PROP_CNTR__BEGIN + 402
    
    # Thread IPv6 counters.
    # Format: `t(LL)t(LL)`
    #
    # The contents include two structs, first one corresponds to
    # all transmit related MAC counters, second one provides the
    # receive related counters.
    #
    # The transmit structure includes:
    #   'L': TxSuccess (The number of IPv6 packets successfully transmitted).
    #   'L': TxFailure (The number of IPv6 packets failed to transmit).
    #
    # The receive structure includes:
    #   'L': RxSuccess (The number of IPv6 packets successfully received).
    #   'L': RxFailure (The number of IPv6 packets failed to receive).
    #
    # Writing to this property with any value would reset all IPv6 counters to zero.
    PROP_CNTR_ALL_IP_COUNTERS = PROP_CNTR__BEGIN + 403

    # MAC retry histogram.
    # Format: t(A(L))t(A(L)) (Read-only)
    #
    # The first structure is histogram which corresponds to retries of direct transmission:
    #   'L': DirectRetry[0]                   (The number of packets send with 0 retransmissions).
    #   'L': DirectRetry[1]                   (The number of packets send with 1 retransmissions).
    #    ...
    #   'L': DirectRetry[n]                   (The number of packets send with n retransmissions).
    #
    # The second structure provides the histogram of retries for indirect transmission:
    #   'L': IndirectRetry[0]                 (The number of packets send with 0 retransmissions).
    #   'L': IndirectRetry[1]                 (The number of packets send with 1 retransmissions).
    #    ...
    #   'L': IndirectRetry[m]                 (The number of packets send with m retransmissions).
    #
    PROP_CNTR_MAC_RETRY_HISTOGRAM = PROP_CNTR__BEGIN + 404

    PROP_CNTR__END = 0x800

    PROP_RCP_EXT__BEGIN = 0x800
    PROP_RCP_MAC_KEY = PROP_RCP_EXT__BEGIN + 0
    PROP_RCP_MAC_FRAME_COUNTER = PROP_RCP_EXT__BEGIN + 1
    PROP_RCP_TIMESTAMP = PROP_RCP_EXT__BEGIN + 2
    PROP_RCP_ENH_ACK_PROBING = PROP_RCP_EXT__BEGIN + 3
    PROP_RCP_CSL_ACCURACY = PROP_RCP_EXT__BEGIN + 4
    PROP_RCP_CSL_UNCERTAINTY = PROP_RCP_EXT__BEGIN + 5
    PROP_RCP_EXT__END = 0x900

    PROP_MULTIPAN__BEGIN = 0x900
    PROP_MULTIPAN_ACTIVE_INTERFACE = PROP_MULTIPAN__BEGIN + 0
    PROP_MULTIPAN__END = 0x910

    PROP_NEST__BEGIN = 0x3BC0
    PROP_NEST_STREAM_MFG = PROP_NEST__BEGIN + 0  # < [U]
    PROP_NEST_LEGACY_ULA_PREFIX = PROP_NEST__BEGIN + 1
    PROP_NEST_LEGACY_LAST_NODE_JOINED = PROP_NEST__BEGIN + 2
    PROP_NEST__END = 0x3C00

    PROP_DEBUG__BEGIN = 0x4000
    PROP_DEBUG_TEST_ASSERT = PROP_DEBUG__BEGIN + 0
    PROP_DEBUG_NCP_LOG_LEVEL = PROP_DEBUG__BEGIN + 1
    PROP_DEBUG_TEST_WATCHDOG = PROP_DEBUG__BEGIN + 2
    PROP_DEBUG_LOG_TIMESTAMP_BASE = PROP_DEBUG__BEGIN + 3
    PROP_DEBUG_TREL_TEST_MODE_ENABLE = PROP_DEBUG__BEGIN + 4
    PROP_DEBUG__END = 0x4400

    #=========================================

    MAC_FILTER_MDOE_NORMAL = 0
    MAC_FILTER_MODE_PROMISCUOUS = 1
    MAC_FILTER_MODE_MONITOR = 2

    #=========================================

    RSSI_OVERRIDE = 127

    #=========================================

    SCAN_STATE_IDLE = 0
    SCAN_STATE_BEACON = 1
    SCAN_STATE_ENERGY = 2
    SCAN_STATE_DISCOVER = 3

    #=========================================

    # Describes the supported capabilities of NCP.
    CAP_OPENTHREAD__BEGIN = 512

    CAP_MAC_RETRY_HISTOGRAM = CAP_OPENTHREAD__BEGIN + 12


class kThread(object):
    """ OpenThread constant class. """
    PrefixPreferenceOffset = 6
    PrefixPreferredFlag = 1 << 5
    PrefixSlaacFlag = 1 << 4
    PrefixDhcpFlag = 1 << 3
    PrefixConfigureFlag = 1 << 2
    PrefixDefaultRouteFlag = 1 << 1
    PrefixOnMeshFlag = 1 << 0


#=========================================

SPINEL_LAST_STATUS_MAP = {
    0:
        "STATUS_OK: Operation has completed successfully.",
    1:
        "STATUS_FAILURE: Operation has failed for some undefined reason.",
    2:
        "STATUS_UNIMPLEMENTED: The given operation has not been implemented.",
    3:
        "STATUS_INVALID_ARGUMENT: An argument to the given operation is invalid.",
    4:
        "STATUS_INVALID_STATE : The given operation is invalid for the current state of the device.",
    5:
        "STATUS_INVALID_COMMAND: The given command is not recognized.",
    6:
        "STATUS_INVALID_INTERFACE: The given Spinel interface is not supported.",
    7:
        "STATUS_INTERNAL_ERROR: An internal runtime error has occured.",
    8:
        "STATUS_SECURITY_ERROR: A security or authentication error has occured.",
    9:
        "STATUS_PARSE_ERROR: An error has occured while parsing the command.",
    10:
        "STATUS_IN_PROGRESS: The operation is in progress and will be completed asynchronously.",
    11:
        "STATUS_NOMEM: The operation has been prevented due to memory pressure.",
    12:
        "STATUS_BUSY: The device is currently performing a mutually exclusive operation.",
    13:
        "STATUS_PROPERTY_NOT_FOUND: The given property is not recognized.",
    14:
        "STATUS_PACKET_DROPPED: The packet was dropped.",
    15:
        "STATUS_EMPTY: The result of the operation is empty.",
    16:
        "STATUS_CMD_TOO_BIG: The command was too large to fit in the internal buffer.",
    17:
        "STATUS_NO_ACK: The packet was not acknowledged.",
    18:
        "STATUS_CCA_FAILURE: The packet was not sent due to a CCA failure.",
    19:
        "SPINEL_STATUS_ALREADY: The operation is already in progress.",
    20:
        "SPINEL_STATUS_ITEM_NOT_FOUND: The given item could not be found.",
    21:
        "SPINEL_STATUS_INVALID_COMMAND_FOR_PROP: The given command cannot be performed on this property.",
    22:
        "SPINEL_STATUS_UNKNOWN_NEIGHBOR: The neighbor is unknown.",
    23:
        "SPINEL_STATUS_NOT_CAPABLE: The target is not capable of handling requested operation.",
    24:
        "SPINEL_STATUS_RESPONSE_TIMEOUT: No response received from remote node.",
    25:
        "SPINEL_STATUS_SWITCHOVER_DONE: Radio interface switch completed successfully (SPINEL_PROP_MULTIPAN_ACTIVE_INTERFACE).",
    26:
        "SPINEL_STATUS_SWITCHOVER_FAILED: Radio interface switch failed (SPINEL_PROP_MULTIPAN_ACTIVE_INTERFACE).",
    104:
        "SPINEL_STATUS_JOIN_FAILURE",
    105:
        "SPINEL_STATUS_JOIN_SECURITY: The network key has been set incorrectly.",
    106:
        "SPINEL_STATUS_JOIN_NO_PEERS: The node was unable to find any other peers on the network.",
    107:
        "SPINEL_STATUS_JOIN_INCOMPATIBLE: The only potential peer nodes found are incompatible.",
    108:
        "SPINEL_STATUS_JOIN_RSP_TIMEOUT:  No response in expecting time.",
    109:
        "SPINEL_STATUS_JOIN_SUCCESS: The node succeeds in commissioning and get the network credentials.",
    112:
        "STATUS_RESET_POWER_ON",
    113:
        "STATUS_RESET_EXTERNAL",
    114:
        "STATUS_RESET_SOFTWARE",
    115:
        "STATUS_RESET_FAULT",
    116:
        "STATUS_RESET_CRASH",
    117:
        "STATUS_RESET_ASSERT",
    118:
        "STATUS_RESET_OTHER",
    119:
        "STATUS_RESET_UNKNOWN",
    120:
        "STATUS_RESET_WATCHDOG",
    0x4000:
        "kThreadError_None",
    0x4001:
        "kThreadError_Failed",
    0x4002:
        "kThreadError_Drop",
    0x4003:
        "kThreadError_NoBufs",
    0x4004:
        "kThreadError_NoRoute",
    0x4005:
        "kThreadError_Busy",
    0x4006:
        "kThreadError_Parse",
    0x4007:
        "kThreadError_InvalidArgs",
    0x4008:
        "kThreadError_Security",
    0x4009:
        "kThreadError_AddressQuery",
    0x400A:
        "kThreadError_NoAddress",
    0x400B:
        "kThreadError_NotReceiving",
    0x400C:
        "kThreadError_Abort",
    0x400D:
        "kThreadError_NotImplemented",
    0x400E:
        "kThreadError_InvalidState",
    0x400F:
        "kThreadError_NoTasklets",
}
