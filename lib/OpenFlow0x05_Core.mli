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

type pseudoPort =
  | PhysicalPort of portId
  | InPort
  | Table
  | Normal
  | Flood
  | AllPorts
  | Controller of int16
  | Local
  | Any

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
  
type action =
| Output of pseudoPort
| Group of groupId
| PopVlan
| PushVlan
| PopMpls
| PushMpls
| SetField of oxm
| CopyTtlOut
| CopyTtlIn
| SetNwTtl of int8
| DecNwTtl
| PushPbb
| PopPbb
| SetMplsTtl of int8
| DecMplsTtl
| SetQueue of int32
| Experimenter of int32

type actionSequence = action list

type instruction =
| GotoTable of tableId
| ApplyActions of actionSequence
| WriteActions of actionSequence
| WriteMetadata of int64 mask
| Clear
| Meter of int32
| Experimenter of int32

type switchCapabilities = { flow_stats : bool; table_stats : bool;
                      port_stats : bool; group_stats : bool; ip_reasm : 
                      bool; queue_stats : bool; port_blocked : bool }

type switchFlags = 
  | NormalFrag
  | DropFrag
  | ReasmFrag
  | MaskFrag

type switchConfig = {flags : switchFlags; miss_send_len : int16 }
