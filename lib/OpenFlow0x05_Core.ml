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

let val_to_mask v =
  { m_value = v; m_mask = None }

let ip_to_mask (p,m) =
  if m = 32l then { m_value = p; m_mask = None }
  else { m_value = p; m_mask = Some m }

  
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