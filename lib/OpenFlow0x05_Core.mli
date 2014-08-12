open Packet

type 'a mask = { m_value : 'a; m_mask : 'a option }

type 'a asyncMask = { m_master : 'a ; m_slave : 'a }

type payload =
  | Buffered of int32 * bytes 
    (** [Buffered (id, buf)] is a packet buffered on a switch. *)
  | NotBuffered of bytes

type xid = OpenFlow_Header.xid
type int12 = int16
type int24 = int32
type int128 = int64 * int64


val val_to_mask : 'a1 -> 'a1 mask

val ip_to_mask : (nwAddr * int32) -> nwAddr mask

type switchId = int64

type groupId = int32

type portId = int32

type tableId = int8

type bufferId = int32

type pseudoPort = OpenFlow0x04_Core.pseudoPort

type timeout =
| Permanent
| ExpiresAfter of int16

type experimenter = { experimenter : int32; exp_typ : int32 }

type ethFeatures = { rate_10mb_hd : bool; rate_10mb_fd : bool; 
                     rate_100mb_hd : bool; rate_100mb_fd : bool;
                     rate_1gb_hd : bool; rate_1gb_fd : bool;
                     rate_10gb_fd : bool; rate_40gb_fd : bool;
                     rate_100gb_fd : bool; rate_1tb_fd : bool;
                     other : bool; copper : bool; fiber : bool;
                     autoneg : bool; pause : bool; pause_asym : bool }   

type propEthernet = { curr : ethFeatures;
                      advertised : ethFeatures;
                      supported : ethFeatures; 
                      peer : ethFeatures;
                      curr_speed : int32;
                      max_speed : int32}

type opticalFeatures = { rx_tune : bool; tx_tune : bool; tx_pwr : bool; use_freq : bool}

type propOptical = { supported : opticalFeatures; tx_min_freq_lmda : int32; 
                     tx_max_freq_lmda : int32; tx_grid_freq_lmda : int32;
                     rx_min_freq_lmda : int32; rx_max_freq_lmda : int32; 
                     rx_grid_freq_lmda : int32; tx_pwr_min : int16; tx_pwr_max : int16 }

type portProp = 
  | PropEthernet of propEthernet
  | PropOptical of propOptical
  | PropExp of experimenter

type portState = { link_down : bool; blocked : bool; live : bool }

type portConfig = { port_down : bool; no_recv : bool; no_fwd : bool;
                    no_packet_in : bool }

type portDesc = { port_no : portId;
                  hw_addr : int48;
                  name : string;
                  config : portConfig;
                  state : portState;
                  properties : portProp list
                  }

type oxmIPv6ExtHdr = { noext : bool; esp : bool; auth : bool; dest : bool; frac : bool;
                       router : bool; hop : bool; unrep : bool; unseq : bool }

type oxm =
| OxmInPort of portId
| OxmInPhyPort of portId
| OxmMetadata of int64 mask
| OxmEthType of int16
| OxmEthDst of int48 mask
| OxmEthSrc of int48 mask
| OxmVlanVId of int12 mask
| OxmVlanPcp of int8
| OxmIPProto of int8
| OxmIPDscp of int8
| OxmIPEcn of int8
| OxmIP4Src of int32 mask
| OxmIP4Dst of int32 mask
| OxmTCPSrc of int16
| OxmTCPDst of int16
| OxmARPOp of int16
| OxmARPSpa of int32 mask
| OxmARPTpa of int32 mask
| OxmARPSha of int48 mask
| OxmARPTha of int48 mask
| OxmICMPType of int8
| OxmICMPCode of int8
| OxmMPLSLabel of int32
| OxmMPLSTc of int8
| OxmTunnelId of int64 mask
| OxmUDPSrc of int16
| OxmUDPDst of int16
| OxmSCTPSrc of int16
| OxmSCTPDst of int16
| OxmIPv6Src of int128 mask
| OxmIPv6Dst of int128 mask
| OxmIPv6FLabel of int32 mask
| OxmICMPv6Type of int8
| OxmICMPv6Code of int8
| OxmIPv6NDTarget of int128 mask
| OxmIPv6NDSll of int48
| OxmIPv6NDTll of int48
| OxmMPLSBos of bool
| OxmPBBIsid of int24 mask
| OxmIPv6ExtHdr of oxmIPv6ExtHdr mask
| OxmPBBUCA of bool

type oxmMatch = oxm list

val match_all : oxmMatch

type actionTyp = 
 | Output
 | CopyTTLOut
 | CopyTTLIn
 | SetMPLSTTL
 | DecMPLSTTL
 | PushVLAN
 | PopVLAN
 | PushMPLS
 | PopMPLS
 | SetQueue
 | Group
 | SetNWTTL
 | DecNWTTL
 | SetField
 | PushPBB
 | PopPBB
 | Experimenter

type action = OpenFlow0x04_Core.action

type instruction = OpenFlow0x04_Core.instruction

type switchFlags = 
  | NormalFrag
  | DropFrag
  | ReasmFrag
  | MaskFrag

type tableEviction = { other : bool; importance : bool; lifetime : bool }

type tableVacancy = { vacancy_down : int8; vacancy_up : int8; vacancy : int8 }

type tableProperties = 
  | Eviction of tableEviction
  | Vacancy of tableVacancy
  | Experimenter of experimenter

type tableConfig = { eviction : bool; vacancyEvent : bool }

type tableMod = { table_id : tableId; config : tableConfig; properties : tableProperties list}

type flowModCommand =
| AddFlow
| ModFlow
| ModStrictFlow
| DeleteFlow
| DeleteStrictFlow

type flowModFlags = { fmf_send_flow_rem : bool; fmf_check_overlap : bool;
                      fmf_reset_counts : bool; fmf_no_pkt_counts : bool;
                      fmf_no_byt_counts : bool }

type flowMod = { mfCookie : int64 mask; mfTable_id : tableId;
                 mfCommand : flowModCommand; mfIdle_timeout : timeout;
                 mfHard_timeout : timeout; mfPriority : int16;
                 mfBuffer_id : bufferId option;
                 mfOut_port : pseudoPort option;
                 mfOut_group : groupId option; mfFlags : flowModFlags; mfImportance : int16;
                 mfOfp_match : oxmMatch; mfInstructions : instruction list }

type portModPropEthernet = portState

type portModPropOptical =  { configure : opticalFeatures; freq_lmda : int32; 
                             fl_offset : int32; grid_span : int32; tx_pwr : int32 }

type portModPropt = 
  | PortModPropEthernet of portModPropEthernet
  | PortModPropOptical of portModPropOptical
  | PortModPropExperiment of experimenter

type portMod = { mpPortNo : portId; mpHw_addr : int48; mpConfig : portConfig;
                 mpMask : portConfig; mpProp : portModPropt list }
                 
type flowRequest = OpenFlow0x04_Core.flowRequest

type queueRequest = OpenFlow0x04_Core.queueRequest

type tableFeatures = OpenFlow0x04_Core.tableFeatures

type queueDescRequest = { port_no : pseudoPort; queue_id : int32 }

type flowMonitorFlags = { fmInitial : bool; fmAdd : bool; fmRemoved : bool; fmModify : bool;
                          fmInstructions : bool; fmNoAbvrev : bool; fmOnlyOwn : bool }

type flowMonitorCommand =
  | FMonAdd
  | FMonModify
  | FMonDelete

type flowMonitorReq = { fmMonitor_id : int32; fmOut_port : pseudoPort; fmOut_group : int32;
                        fmFlags : flowMonitorFlags; fmTable_id : int16; fmCommand : 
                        flowMonitorCommand; fmMatch : oxmMatch}

type multipartType =
  | SwitchDescReq
  | PortsDescReq 
  | FlowStatsReq of flowRequest
  | AggregFlowStatsReq of flowRequest
  | TableStatsReq
  | PortStatsReq of portId
  | QueueStatsReq of queueRequest
  | GroupStatsReq of int32
  | GroupDescReq
  | GroupFeatReq
  | MeterStatsReq of int32
  | MeterConfReq of int32
  | MeterFeatReq
  | TableFeatReq of (tableFeatures list) option
  | ExperimentReq of experimenter
  | TableDescReq
  | QueueDescReq of queueDescRequest
  | FlowMonitorReq of flowMonitorReq

type multipartRequest = { mpr_type : multipartType; mpr_flags : bool }

type switchDesc = OpenFlow0x04_Core.switchDesc

type flowStats = OpenFlow0x04_Core.flowStats

type aggregStats = OpenFlow0x04_Core.aggregStats

type tableStats = OpenFlow0x04_Core.tableStats

type portStatsPropEthernet = { rx_frame_err : int64; rx_over_err : int64; rx_crc_err : int64;
                               collisions : int64 }

type portStatsOpticalFlag = { rx_tune : bool; tx_tune : bool; tx_pwr : bool; rx_pwr : bool;
                              tx_bias : bool; tx_temp : bool }

type portStatsPropOptical = { flags : portStatsOpticalFlag; tx_freq_lmda : int32;
                              tx_offset : int32; tx_grid_span : int32; rx_freq_lmda : int32;
                              rx_offset : int32; rx_grid_span : int32; tx_pwr : int16; rx_pwr : int16;
                              bias_current : int16; temperature : int16 }

type portStatsProp = 
  | PortStatsPropEthernet of portStatsPropEthernet
  | PortStatsPropOptical of portStatsPropOptical
  | PortStatsPropExperimenter of experimenter

type portStats = { psPort_no : portId; duration_sec : int32; duration_nsec : int32 ;
                   rx_packets : int64; tx_packets : int64; 
                   rx_bytes : int64; tx_bytes : int64; rx_dropped : int64; 
                   tx_dropped : int64; rx_errors : int64; tx_errors : int64;
                   properties : portStatsProp list}

type queueStatsProp = 
  | ExperimenterQueueStats of experimenter

type queueStats = { qsPort_no : portId; queue_id : int32; tx_bytes : int64; tx_packets : int64;
                    tx_errors : int64; duration_sec : int32; duration_nsec : int32;
                    properties : queueStatsProp list }

type groupStats = OpenFlow0x04_Core.groupStats

type groupDesc = OpenFlow0x04_Core.groupDesc

type groupFeatures = OpenFlow0x04_Core.groupFeatures

type meterStats = OpenFlow0x04_Core.meterStats

type meterConfig = OpenFlow0x04_Core.meterConfig

type meterFeaturesStats = OpenFlow0x04_Core.meterFeaturesStats

type multipartReplyTyp = 
  | PortsDescReply of portDesc list
  | SwitchDescReply of switchDesc
  | FlowStatsReply of flowStats list
  | AggregateReply of aggregStats
  | TableReply of tableStats list
  | TableFeaturesReply of tableFeatures list
  | PortStatsReply of portStats list
  | QueueStatsReply of queueStats list
  | GroupStatsReply of groupStats list
  | GroupDescReply of groupDesc list
  | GroupFeaturesReply of groupFeatures
  | MeterReply of meterStats list
  | MeterConfig of meterConfig list
  | MeterFeaturesReply of meterFeaturesStats

type multipartReply = {mpreply_typ : multipartReplyTyp; mpreply_flags : bool}