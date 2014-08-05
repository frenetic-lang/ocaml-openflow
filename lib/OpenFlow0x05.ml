(** OpenFlow 1.4 (protocol version 0x05) *)

open Printf
open Cstruct
open Cstruct.BE

open OpenFlow0x05_Core
open List
open Packet

exception Unparsable of string
let sym_num = ref 0

let sum (lst : int list) = List.fold_left (fun x y -> x + y) 0 lst

type uint128 = int64*int64
type uint48 = uint64
type uint24 = int32
type uint12 = uint16
type switchId = OpenFlow0x05_Core.switchId

let rec marshal_fields (buf: Cstruct.t) (fields : 'a list) (marshal_func : Cstruct.t -> 'a -> int ): int =
  if (fields = []) then 0
  else let size = marshal_func buf (List.hd fields) in
    size + (marshal_fields (Cstruct.shift buf size) (List.tl fields) marshal_func)

let parse_fields (bits : Cstruct.t) (parse_func : Cstruct.t -> 'a) (length_func : Cstruct.t -> int option) :'a list =
  let iter =
    Cstruct.iter
        length_func
        parse_func
        bits in
    List.rev (Cstruct.fold (fun acc bits -> bits :: acc) iter [])

let pad_to_64bits (n : int) : int =
  if n land 0x7 <> 0 then
    n + (8 - (n land 0x7))
  else
    n

cstruct ofp_uint8 {
  uint8_t value
} as big_endian

cstruct ofp_uint16 {
  uint16_t value
} as big_endian

cstruct ofp_uint24 {
  uint16_t high;
  uint8_t low
} as big_endian

cstruct ofp_uint32 {
  uint32_t value
} as big_endian

cstruct ofp_uint48 {
  uint32_t high;
  uint16_t low
} as big_endian

cstruct ofp_uint64 {
  uint64_t value
} as big_endian

cstruct ofp_uint128 {
  uint64_t high;
  uint64_t low
} as big_endian

let max_uint32 = 4294967296L (* = 2^32*)

let compare_uint32 a b =
(* val compare_uint32 : uint32 -> uint32 -> bool ; return a < b, for a, b uint32  *)
    let a' = if a < 0l then  
                Int64.sub max_uint32 (Int64.of_int32 (Int32.abs a))
             else Int64.of_int32 a in
    let b' = if b < 0l then
                Int64.sub max_uint32 (Int64.of_int32 (Int32.abs b))
             else Int64.of_int32 b in
    a' <= b'

let set_ofp_uint48_value (buf : Cstruct.t) (value : uint48) =
  let high = Int64.to_int32 (Int64.shift_right_logical  value 16) in
    let low = ((Int64.to_int value) land 0xffff) in
      set_ofp_uint48_high buf high;
      set_ofp_uint48_low buf low

let get_ofp_uint48_value (buf : Cstruct.t) : uint48 =
  let highBits = get_ofp_uint48_high buf in
  let high = Int64.shift_left (
    if highBits < 0l then
      Int64.sub max_uint32 (Int64.of_int32 (Int32.abs highBits))
    else
      Int64.of_int32 highBits) 16 in
  let low = Int64.of_int (get_ofp_uint48_low buf) in
  Int64.logor low high

let get_ofp_uint24_value (buf : Cstruct.t) : uint24 =
  let high = Int32.shift_left (Int32.of_int (get_ofp_uint24_high buf)) 8 in
  let low = Int32.of_int (get_ofp_uint24_low buf )in
  Int32.logor high low

let set_ofp_uint24_value (buf : Cstruct.t) (value : uint24) =
  let high = (Int32.to_int value) lsr 8 in
  let low = (Int32.to_int value) land 0xff in
    set_ofp_uint24_high buf high;
    set_ofp_uint24_low buf low

let set_ofp_uint128_value (buf : Cstruct.t) ((h,l) : uint128) =
  set_ofp_uint128_high buf h;
  set_ofp_uint128_low buf l

let get_ofp_uint128_value (buf : Cstruct.t) : uint128 =
  (get_ofp_uint128_high buf, get_ofp_uint128_low buf)

let rec pad_with_zeros (buf : Cstruct.t) (pad : int) : int =
  if pad = 0 then 0
  else begin set_ofp_uint8_value buf 0;
    1 + pad_with_zeros (Cstruct.shift buf 1) (pad - 1) end

let test_bit16 (n:int) (x:int) : bool =
  (x lsr n) land 1 = 1

cenum msg_code {
  HELLO                 = 0;
  ERROR                 = 1;
  ECHO_REQ              = 2;
  ECHO_RESP             = 3;
  EXPERIMENTER          = 4;
  FEATURES_REQ          = 5;
  FEATURES_RESP         = 6;
  GET_CONFIG_REQ        = 7;
  GET_CONFIG_RESP       = 8;
  SET_CONFIG            = 9;
  PACKET_IN             = 10;
  FLOW_REMOVED          = 11;
  PORT_STATUS           = 12;
  PACKET_OUT            = 13;
  FLOW_MOD              = 14;
  GROUP_MOD             = 15;
  PORT_MOD              = 16;
  TABLE_MOD             = 17;
  MULTIPART_REQ         = 18;
  MULTIPART_RESP        = 19;
  BARRIER_REQ           = 20;
  BARRIER_RESP          = 21;
  ROLE_REQ              = 24;
  ROLE_RESP             = 25;
  GET_ASYNC_REQ         = 26;
  GET_ASYNC_REP         = 27;
  SET_ASYNC             = 28;
  METER_MOD             = 29;
  ROLE_STATUS           = 30;
  TABLE_STATUS          = 31;
  REQUEST_FORWARD       = 32;
  BUNDLE_CONTROL        = 33;
  BUNDLE_ADD_MESSAGE    = 34
} as uint8_t

(* Common Structures *)
module PortDesc = struct

  cstruct ofp_port {
    uint32_t port_no;
    uint16_t length;
    uint16_t pad;
    uint8_t hw_addr[6];
    uint16_t pad2;
    uint8_t name[16]; (* OFP_MAX_PORT_NAME_LEN, Null-terminated *)
    uint32_t config; (* Bitmap of OFPPC_* flags. *)
    uint32_t state; (* Bitmap of OFPPS_* flags. *)
  } as big_endian

  module Config = struct

    type t = portConfig

    let config_to_int (config : portConfig) : int32 =
      Int32.logor (if config.port_down then (Int32.shift_left 1l 0) else 0l) 
       (Int32.logor (if config.no_recv then (Int32.shift_left 1l 2) else 0l)  
        (Int32.logor (if config.no_fwd then (Int32.shift_left 1l 5) else 0l)
         (if config.no_packet_in then (Int32.shift_left 1l 6) else 0l)))

    let marshal (pc : portConfig) : int32 = config_to_int pc

    let parse bits : portConfig =
      { port_down     = Bits.test_bit 0 bits;
        no_recv       = Bits.test_bit 2 bits;
        no_fwd        = Bits.test_bit 5 bits;
        no_packet_in  = Bits.test_bit 6 bits
      }

    let to_string (config : portConfig) = 
      Format.sprintf "{ port_down = %b; no_recv = %b; no_fwd  = %b; no_packet_in = %b }"
      config.port_down
      config.no_recv
      config.no_fwd
      config.no_packet_in
  end

  module State = struct

    type t = portState

    let state_to_int (state : portState) : int32 =
      Int32.logor (if state.link_down then (Int32.shift_left 1l 0) else 0l) 
       (Int32.logor (if state.blocked then (Int32.shift_left 1l 1) else 0l)  
        (if state.live then (Int32.shift_left 1l 2) else 0l))

    let marshal (ps : portState) : int32 = state_to_int ps

    let parse bits : portState =
      { link_down = Bits.test_bit 0 bits;
        blocked = Bits.test_bit 1 bits;
        live = Bits.test_bit 2 bits
      }

    let to_string (state : portState) =
      Format.sprintf "{ link_down = %B; blocked = %B; live = %B }"
      state.link_down
      state.blocked
      state.live
  end

  module Properties = struct

    module EthFeatures = struct
      let features_to_int (features : ethFeatures) : int32 =
        Int32.logor (if features.rate_10mb_hd then (Int32.shift_left 1l 0) else 0l)
        (Int32.logor (if features.rate_10mb_fd then (Int32.shift_left 1l 1) else 0l)
         (Int32.logor (if features.rate_100mb_hd then (Int32.shift_left 1l 2) else 0l)
          (Int32.logor (if features.rate_100mb_fd then (Int32.shift_left 1l 3) else 0l)
           (Int32.logor (if features.rate_1gb_hd then (Int32.shift_left 1l 4) else 0l)
            (Int32.logor (if features.rate_1gb_fd then (Int32.shift_left 1l 5) else 0l)
             (Int32.logor (if features.rate_10gb_fd then (Int32.shift_left 1l 6) else 0l)
              (Int32.logor (if features.rate_40gb_fd then (Int32.shift_left 1l 7) else 0l)
               (Int32.logor (if features.rate_100gb_fd then (Int32.shift_left 1l 8) else 0l)
                (Int32.logor (if features.rate_1tb_fd then (Int32.shift_left 1l 9) else 0l)
                 (Int32.logor (if features.other then (Int32.shift_left 1l 10) else 0l)
                  (Int32.logor (if features.copper then (Int32.shift_left 1l 11) else 0l)
                   (Int32.logor (if features.fiber then (Int32.shift_left 1l 12) else 0l)
                    (Int32.logor (if features.autoneg then (Int32.shift_left 1l 13) else 0l)
                     (Int32.logor (if features.pause then (Int32.shift_left 1l 14) else 0l)
                      (if features.pause_asym then (Int32.shift_left 1l 15) else 0l)))))))))))))))

      let marshal (pf : ethFeatures) : int32 = features_to_int pf

      let parse bits : ethFeatures =
        { rate_10mb_hd  = Bits.test_bit 0 bits;
          rate_10mb_fd  = Bits.test_bit 1 bits;
          rate_100mb_hd = Bits.test_bit 2 bits;
          rate_100mb_fd = Bits.test_bit 3 bits;
          rate_1gb_hd   = Bits.test_bit 4 bits;
          rate_1gb_fd   = Bits.test_bit 5 bits;
          rate_10gb_fd  = Bits.test_bit 6 bits;
          rate_40gb_fd  = Bits.test_bit 7 bits;
          rate_100gb_fd = Bits.test_bit 8 bits;
          rate_1tb_fd   = Bits.test_bit 9 bits;
          other         = Bits.test_bit 10 bits;
          copper        = Bits.test_bit 11 bits;
          fiber         = Bits.test_bit 12 bits;
          autoneg       = Bits.test_bit 13 bits;
          pause         = Bits.test_bit 14 bits;
          pause_asym    = Bits.test_bit 15 bits
        }

      let to_string (feat : ethFeatures) =
        Format.sprintf
          "{ 10mhd = %B; 10mfd  = %B; 100mhd  = %B; 100mfd  = %B; 1ghd%B\
          1gfd  = %B; 10gfd  = %B; 40gfd  = %B; 100gfd  = %B; 1tfd  = %B; \
          other  = %B; copper  = %B; fiber  = %B; autoneg  = %B; pause  = %B; \
          pause_asym  = %B }"
          feat.rate_10mb_hd
          feat.rate_10mb_fd
          feat.rate_100mb_hd
          feat.rate_100mb_fd
          feat.rate_1gb_hd
          feat.rate_1gb_fd
          feat.rate_10gb_fd
          feat.rate_40gb_fd
          feat.rate_100gb_fd
          feat.rate_1tb_fd
          feat.other
          feat.copper
          feat.fiber
          feat.autoneg
          feat.pause
          feat.pause_asym

    end

    module OptFeatures = struct

      let marshal (optFeat : opticalFeatures) : int32 =
        Int32.logor (if optFeat.rx_tune then (Int32.shift_left 1l 0) else 0l)
          (Int32.logor (if optFeat.tx_tune then (Int32.shift_left 1l 1) else 0l)
            (Int32.logor (if optFeat.tx_pwr then (Int32.shift_left 1l 2) else 0l)
              (if optFeat.use_freq then (Int32.shift_left 1l 3) else 0l)))

      let parse bits : opticalFeatures =
        { rx_tune  = Bits.test_bit 0 bits
        ; tx_tune  = Bits.test_bit 1 bits
        ; tx_pwr   = Bits.test_bit 2 bits
        ; use_freq = Bits.test_bit 3 bits }

      let to_string (optFeat : opticalFeatures) : string =
        Format.sprintf "{ rx_tune : %B; tx_tune : %B; tw_pwr : %B; use_freq : %B }"
        optFeat.rx_tune
        optFeat.tx_tune
        optFeat.tx_pwr
        optFeat.use_freq

    end

    cstruct ofp_port_desc_prop_header {
      uint16_t typ;
      uint16_t len
    } as big_endian

    cstruct ofp_port_desc_prop_ethernet {
      uint16_t typ;
      uint16_t len;
      uint8_t pad[4];
      uint32_t curr;
      uint32_t advertised;
      uint32_t supported;
      uint32_t peer;
      uint32_t curr_speed;
      uint32_t max_speed
    } as big_endian

    cstruct ofp_port_desc_prop_optical {
      uint16_t typ;
      uint16_t len;
      uint8_t pad[4];
      uint32_t supported;
      uint32_t tx_min_freq_lmda;
      uint32_t tx_max_freq_lmda;
      uint32_t tx_grid_freq_lmda;
      uint32_t rx_min_freq_lmda;
      uint32_t rx_max_freq_lmda;
      uint32_t rx_grid_freq_lmda;
      uint16_t tx_pwr_min;
      uint16_t tx_pwr_max
    } as big_endian

    cstruct ofp_port_desc_prop_experimenter {
      uint16_t typ;
      uint16_t len;
      uint32_t experimenter;
      uint32_t exp_typ
    } as big_endian

    cenum ofp_port_desc_prop_type {
      OFPPDPT_ETHERNET = 0;
      OFPPDPT_OPTICAL = 1;
      OFPPDPT_EXPERIMENTER = 0xFFFF
    } as uint16_t

    type t = portProp

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_port_desc_prop_header then None
      else Some (get_ofp_port_desc_prop_ethernet_len buf)

    let sizeof (prop : t) : int =
      match prop with
        | PropEthernet _ -> 32
        | PropOptical _ -> 40
        | PropExp _ -> 12

    let to_string (prop : t) : string =
     match prop with
       | PropEthernet p -> 
          Format.sprintf "Ethernet { curr = %s; advertised = %s; \
                            supported = %s; peer = %s; \
                            curr_speed = %lu; max_speed = %lu }"
          (EthFeatures.to_string p.curr)
          (EthFeatures.to_string p.advertised)
          (EthFeatures.to_string p.supported)
          (EthFeatures.to_string p.peer)
          p.curr_speed
          p.max_speed
       | PropOptical p -> 
         Format.sprintf "Optical { supported : %s; tx_min_freq_lmda : %lu; tx_max_freq_lmda : %lu; \
                           tx_grid_freq_lmda : %lu; rx_min_freq_lmda : %lu; rx_max_freq_lmda : %lu; \
                           rx_grid_freq_lmda : %lu; tx_pwr_min : %u; tx_pwr_max : %u }"
         (OptFeatures.to_string p.supported)
         p.tx_min_freq_lmda
         p.tx_max_freq_lmda
         p.tx_grid_freq_lmda
         p.rx_min_freq_lmda
         p.rx_max_freq_lmda
         p.rx_grid_freq_lmda
         p.tx_pwr_min
         p.tx_pwr_max
       | PropExp p ->
         Format.sprintf "Experimenter { experimenter : %lu; exp_typ : %lu }"
         p.experimenter
         p.exp_typ

    let marshal (buf : Cstruct.t) (prop : t) : int =
      match prop with
        | PropEthernet p ->
          set_ofp_port_desc_prop_ethernet_typ buf (ofp_port_desc_prop_type_to_int OFPPDPT_ETHERNET);
          set_ofp_port_desc_prop_ethernet_len buf (sizeof prop);
          set_ofp_port_desc_prop_ethernet_curr buf (EthFeatures.marshal p.curr);
          set_ofp_port_desc_prop_ethernet_advertised buf (EthFeatures.marshal p.advertised);
          set_ofp_port_desc_prop_ethernet_supported buf (EthFeatures.marshal p.supported);
          set_ofp_port_desc_prop_ethernet_peer buf (EthFeatures.marshal p.peer);
          set_ofp_port_desc_prop_ethernet_curr_speed buf p.curr_speed;
          set_ofp_port_desc_prop_ethernet_max_speed buf p.max_speed;
          sizeof prop
        | PropOptical p ->
          set_ofp_port_desc_prop_optical_typ buf (ofp_port_desc_prop_type_to_int OFPPDPT_OPTICAL);
          set_ofp_port_desc_prop_optical_len buf (sizeof prop);
          set_ofp_port_desc_prop_optical_supported buf (OptFeatures.marshal p.supported);
          set_ofp_port_desc_prop_optical_tx_min_freq_lmda buf p.tx_min_freq_lmda;
          set_ofp_port_desc_prop_optical_tx_max_freq_lmda buf p.tx_max_freq_lmda;
          set_ofp_port_desc_prop_optical_tx_grid_freq_lmda buf p.tx_grid_freq_lmda;
          set_ofp_port_desc_prop_optical_rx_min_freq_lmda buf p.rx_min_freq_lmda;
          set_ofp_port_desc_prop_optical_rx_max_freq_lmda buf p.rx_max_freq_lmda;
          set_ofp_port_desc_prop_optical_rx_grid_freq_lmda buf p.rx_grid_freq_lmda;
          set_ofp_port_desc_prop_optical_tx_pwr_min buf p.tx_pwr_min;
          set_ofp_port_desc_prop_optical_tx_pwr_max buf p.tx_pwr_max;
          sizeof prop
        | PropExp p ->
          set_ofp_port_desc_prop_experimenter_typ buf (ofp_port_desc_prop_type_to_int OFPPDPT_EXPERIMENTER);
          set_ofp_port_desc_prop_experimenter_len buf  (sizeof prop);
          set_ofp_port_desc_prop_experimenter_experimenter buf p.experimenter;
          set_ofp_port_desc_prop_experimenter_exp_typ buf p.exp_typ;
          sizeof prop

    let parse (bits : Cstruct.t) : t =
      let typ = match int_to_ofp_port_desc_prop_type (get_ofp_port_desc_prop_header_typ bits) with
        | Some v -> v
        | None -> raise (Unparsable (sprintf "malformed prop typ")) in
      match typ with
        | OFPPDPT_ETHERNET -> PropEthernet { curr = EthFeatures.parse (get_ofp_port_desc_prop_ethernet_curr bits)
                                           ; advertised = EthFeatures.parse (get_ofp_port_desc_prop_ethernet_advertised bits)
                                           ; supported = EthFeatures.parse (get_ofp_port_desc_prop_ethernet_supported bits)
                                           ; peer = EthFeatures.parse (get_ofp_port_desc_prop_ethernet_peer bits)
                                           ; curr_speed = get_ofp_port_desc_prop_ethernet_curr_speed bits
                                           ; max_speed = get_ofp_port_desc_prop_ethernet_max_speed bits}
        | OFPPDPT_OPTICAL -> PropOptical { supported = OptFeatures.parse (get_ofp_port_desc_prop_optical_supported bits)
                                         ; tx_min_freq_lmda = get_ofp_port_desc_prop_optical_tx_min_freq_lmda bits
                                         ; tx_max_freq_lmda = get_ofp_port_desc_prop_optical_tx_max_freq_lmda bits
                                         ; tx_grid_freq_lmda = get_ofp_port_desc_prop_optical_tx_grid_freq_lmda bits
                                         ; rx_min_freq_lmda = get_ofp_port_desc_prop_optical_rx_min_freq_lmda bits
                                         ; rx_max_freq_lmda = get_ofp_port_desc_prop_optical_rx_max_freq_lmda bits
                                         ; rx_grid_freq_lmda = get_ofp_port_desc_prop_optical_rx_grid_freq_lmda bits
                                         ; tx_pwr_min = get_ofp_port_desc_prop_optical_tx_pwr_min bits
                                         ; tx_pwr_max = get_ofp_port_desc_prop_optical_tx_pwr_max bits }
        | OFPPDPT_EXPERIMENTER -> PropExp { experimenter = get_ofp_port_desc_prop_experimenter_experimenter bits
                                          ; exp_typ = get_ofp_port_desc_prop_experimenter_exp_typ bits}
  end

  type t = portDesc

  let sizeof (p : portDesc) =
  sizeof_ofp_port + sum (map Properties.sizeof p.properties)

  let marshal (buf : Cstruct.t) (desc : portDesc) : int =
    let size = sizeof desc in
    set_ofp_port_port_no buf desc.port_no;
    set_ofp_port_length buf size;
    set_ofp_port_pad buf 0;
    set_ofp_port_hw_addr (bytes_of_mac desc.hw_addr) 0 buf;
    set_ofp_port_pad2 buf 0;
    set_ofp_port_name desc.name 0 buf;
    set_ofp_port_config buf (Config.marshal desc.config);
    set_ofp_port_state buf (State.marshal desc.state);
    sizeof_ofp_port + marshal_fields (Cstruct.shift buf sizeof_ofp_port) desc.properties Properties.marshal
    
	    
  let parse (bits : Cstruct.t) : portDesc =
    let port_no = get_ofp_port_port_no bits in
    let hw_addr = mac_of_bytes (copy_ofp_port_hw_addr bits) in
    let name = copy_ofp_port_name bits in
    let state = State.parse (get_ofp_port_state bits) in
    let config = Config.parse (get_ofp_port_config bits) in
    let properties = parse_fields (Cstruct.shift bits sizeof_ofp_port) Properties.parse Properties.length_func in
    { port_no;
      hw_addr;
      name;
      config; 
      state;
      properties}
      
  let to_string (port : portDesc) =
    Format.sprintf " { port_no : %lu; hw_addr : %s; name : %s; config : %s; \
                       state : %s; properties : %s }"
        port.port_no
        (string_of_mac port.hw_addr)
        port.name
        (Config.to_string port.config)
        (State.to_string port.state)
        ("[ " ^ (String.concat "; " (map Properties.to_string port.properties)) ^ " ]")


  let length_func = (fun buf -> Some sizeof_ofp_port)
end

cstruct ofp_oxm {
  uint16_t oxm_class;
  uint8_t oxm_field_and_hashmask;
  uint8_t oxm_length
} as big_endian

module Oxm = struct

  cenum ofp_oxm_class {
    OFPXMC_NXM_0          = 0x0000;    (* Backward compatibility with NXM *)
    OFPXMC_NXM_1          = 0x0001;    (* Backward compatibility with NXM *)
    OFPXMC_OPENFLOW_BASIC = 0x8000;    (* Basic class for OpenFlow *)
    OFPXMC_EXPERIMENTER   = 0xFFFF     (* Experimenter class *)
  } as uint16_t

  cenum oxm_ofb_match_fields {
    OFPXMT_OFB_IN_PORT        = 0;  (* Switch input port. *)
    OFPXMT_OFB_IN_PHY_PORT    = 1;  (* Switch physical input port. *)
    OFPXMT_OFB_METADATA       = 2;  (* Metadata passed between tables. *)
    OFPXMT_OFB_ETH_DST        = 3;  (* Ethernet destination address. *)
    OFPXMT_OFB_ETH_SRC        = 4;  (* Ethernet source address. *)
    OFPXMT_OFB_ETH_TYPE       = 5;  (* Ethernet frame type. *)
    OFPXMT_OFB_VLAN_VID       = 6;  (* VLAN id. *)
    OFPXMT_OFB_VLAN_PCP       = 7;  (* VLAN priority. *)
    OFPXMT_OFB_IP_DSCP        = 8;  (* IP DSCP (6 bits in ToS field). *)
    OFPXMT_OFB_IP_ECN         = 9;  (* IP ECN (2 bits in ToS field). *)
    OFPXMT_OFB_IP_PROTO       = 10; (* IP protocol. *)
    OFPXMT_OFB_IPV4_SRC       = 11; (* IPv4 source address. *)
    OFPXMT_OFB_IPV4_DST       = 12; (* IPv4 destination address. *)
    OFPXMT_OFB_TCP_SRC        = 13; (* TCP source port. *)
    OFPXMT_OFB_TCP_DST        = 14; (* TCP destination port. *)
    OFPXMT_OFB_UDP_SRC        = 15; (* UDP source port. *)
    OFPXMT_OFB_UDP_DST        = 16; (* UDP destination port. *)
    OFPXMT_OFB_SCTP_SRC       = 17; (* SCTP source port. *)
    OFPXMT_OFB_SCTP_DST       = 18; (* SCTP destination port. *)
    OFPXMT_OFB_ICMPV4_TYPE    = 19; (* ICMP type. *)
    OFPXMT_OFB_ICMPV4_CODE    = 20; (* ICMP code. *)
    OFPXMT_OFB_ARP_OP         = 21; (* ARP opcode. *)
    OFPXMT_OFB_ARP_SPA        = 22; (* ARP source IPv4 address. *)
    OFPXMT_OFB_ARP_TPA        = 23; (* ARP target IPv4 address. *)
    OFPXMT_OFB_ARP_SHA        = 24; (* ARP source hardware address. *)
    OFPXMT_OFB_ARP_THA        = 25; (* ARP target hardware address. *)
    OFPXMT_OFB_IPV6_SRC       = 26; (* IPv6 source address. *)
    OFPXMT_OFB_IPV6_DST       = 27; (* IPv6 destination address. *)
    OFPXMT_OFB_IPV6_FLABEL    = 28; (* IPv6 Flow Label *)
    OFPXMT_OFB_ICMPV6_TYPE    = 29; (* ICMPv6 type. *)
    OFPXMT_OFB_ICMPV6_CODE    = 30; (* ICMPv6 code. *)
    OFPXMT_OFB_IPV6_ND_TARGET = 31; (* Target address for ND. *)
    OFPXMT_OFB_IPV6_ND_SLL    = 32; (* Source link-layer for ND. *)
    OFPXMT_OFB_IPV6_ND_TLL    = 33; (* Target link-layer for ND. *)
    OFPXMT_OFB_MPLS_LABEL     = 34; (* MPLS label. *)
    OFPXMT_OFB_MPLS_TC        = 35; (* MPLS TC. *)
    OFPXMT_OFP_MPLS_BOS       = 36; (* MPLS BoS bit. *)
    OFPXMT_OFB_PBB_ISID       = 37; (* PBB I-SID. *)
    OFPXMT_OFB_TUNNEL_ID      = 38; (* Logical Port Metadata. *)
    OFPXMT_OFB_IPV6_EXTHDR    = 39; (* IPv6 Extension Header pseudo-field *)
    OFPXMT_OFB_PBB_UCA        = 41  (* PBB UCA header field *)
  } as uint8_t

  module IPv6ExtHdr = struct
  
    type t = oxmIPv6ExtHdr

    let marshal (hdr : t) : int16 = 
      (if hdr.noext then 1 lsl 0 else 0) lor
        (if hdr.esp then 1 lsl 1 else 0) lor
          (if hdr.auth then 1 lsl 2 else 0) lor
            (if hdr.dest then 1 lsl 3 else 0) lor
              (if hdr.frac then 1 lsl 4 else 0) lor
                (if hdr.router then 1 lsl 5 else 0) lor
                  (if hdr.hop then 1 lsl 6 else 0) lor
                    (if hdr.unrep then 1 lsl 7 else 0) lor
                      (if hdr.unseq then 1 lsl 8 else 0)

    let parse bits : t = 
      { noext = test_bit16 0 bits
      ; esp = test_bit16 1 bits
      ; auth = test_bit16 2 bits
      ; dest = test_bit16 3 bits
      ; frac = test_bit16 4 bits
      ; router = test_bit16 5 bits
      ; hop = test_bit16 6 bits
      ; unrep = test_bit16 7 bits
      ; unseq = test_bit16 8 bits}

    let to_string (t : t) : string = 
      Format.sprintf "{ noext = %B; esp = %B; auth = %B; dest = %B; frac = %B; router = %B; \
                        hop = %B; unrep = %B; unseq = %B }"
      t.noext
      t.esp
      t.auth
      t.dest
      t.frac
      t.router
      t.hop
      t.unrep
      t.unseq
  end

  type t = oxm

  let field_length (oxm : oxm) : int = match oxm with
    | OxmInPort _ -> 4
    | OxmInPhyPort _ -> 4
    | OxmEthType  _ -> 2
    | OxmEthDst ethaddr ->
      (match ethaddr.m_mask with
        | None -> 6
        | Some _ -> 12)
    | OxmEthSrc ethaddr ->
      (match ethaddr.m_mask with
        | None -> 6
        | Some _ -> 12)
    | OxmVlanVId vid ->
      (match vid.m_mask with
        | None -> 2
        | Some _ -> 4)
    | OxmVlanPcp _ -> 1
    | OxmIP4Src ipaddr -> 
      (match ipaddr.m_mask with
        | None -> 4
        | Some _ -> 8)
    | OxmIP4Dst ipaddr ->       
      (match ipaddr.m_mask with
        | None -> 4
        | Some _ -> 8)
    | OxmTCPSrc _ -> 2
    | OxmTCPDst _ -> 2
    | OxmARPOp _ -> 2
    | OxmARPSpa t->
      (match t.m_mask with
        | None -> 4
        | Some _ -> 8)
    | OxmARPTpa t->
      (match t.m_mask with
        | None -> 4
        | Some _ -> 8)
    | OxmARPSha t->
      (match t.m_mask with
        | None -> 6
        | Some _ -> 12)
    | OxmARPTha t->
      (match t.m_mask with
        | None -> 6
        | Some _ -> 12)
    | OxmMPLSLabel _ -> 4
    | OxmMPLSTc _ -> 1
    | OxmMetadata t -> 
      (match t.m_mask with
        | None -> 8
        | Some _ -> 16)
    | OxmIPProto _ -> 1
    | OxmIPDscp _ -> 1
    | OxmIPEcn _ -> 1
    | OxmICMPType _ -> 1
    | OxmICMPCode _ -> 1
    | OxmTunnelId t ->
      (match t.m_mask with
        | None -> 8
        | Some _ -> 16)
    | OxmUDPSrc _ -> 2
    | OxmUDPDst _ -> 2
    | OxmSCTPSrc _ -> 2
    | OxmSCTPDst _ -> 2
    | OxmIPv6Src t ->
      (match t.m_mask with
        | None -> 16
        | Some _ -> 32)
    | OxmIPv6Dst t ->
      (match t.m_mask with
        | None -> 16
        | Some _ -> 32)
    | OxmIPv6FLabel t ->
      (match t.m_mask with
        | None -> 4
        | Some _ -> 8)
    | OxmICMPv6Type _ -> 1
    | OxmICMPv6Code _ -> 1
    | OxmIPv6NDTarget t ->
      (match t.m_mask with
        | None -> 16
        | Some _ -> 32)
    | OxmIPv6NDSll _ -> 6
    | OxmIPv6NDTll _ -> 6
    | OxmMPLSBos _ -> 1
    | OxmPBBIsid t ->
      (match t.m_mask with
        | None -> 3
        | Some _ -> 6)
    | OxmIPv6ExtHdr t ->
      (match t.m_mask with
        | None -> 2
        | Some _ -> 4)
    | OxmPBBUCA _ -> 1

  let field_name (oxm : oxm) : string = match oxm with
    | OxmInPort _ -> "InPort"
    | OxmInPhyPort _ -> "InPhyPort"
    | OxmEthType  _ -> "EthType"
    | OxmEthDst ethaddr ->
      (match ethaddr.m_mask with
        | None -> "EthDst"
        | Some _ -> "EthDst/mask")
    | OxmEthSrc ethaddr ->
      (match ethaddr.m_mask with
        | None -> "EthSrc"
        | Some _ -> "EthSrc/mask")
    | OxmVlanVId vid ->
      (match vid.m_mask with
        | None -> "VlanVId"
        | Some _ -> "VlanVId/mask")
    | OxmVlanPcp _ -> "VlanPcp"
    | OxmIP4Src ipaddr -> 
      (match ipaddr.m_mask with
        | None -> "IPSrc"
        | Some _ -> "IPSrc/mask")
    | OxmIP4Dst ipaddr ->       
      (match ipaddr.m_mask with
        | None -> "IPDst"
        | Some _ -> "IPDst/mask")
    | OxmTCPSrc _ -> "TCPSrc"
    | OxmTCPDst _ -> "TCPDst"
    | OxmARPOp _ -> "ARPOp"
    | OxmARPSpa t->
      (match t.m_mask with
        | None -> "ARPSpa"
        | Some _ -> "ARPSpa/mask")
    | OxmARPTpa t->
      (match t.m_mask with
        | None -> "ARPTpa"
        | Some _ -> "ARPTpa/mask")
    | OxmARPSha t->
      (match t.m_mask with
        | None -> "ARPSha"
        | Some _ -> "ARPSha/mask")
    | OxmARPTha t->
      (match t.m_mask with
        | None -> "ARPTha"
        | Some _ -> "ARPTha/mask")
    | OxmMPLSLabel _ -> "MPLSLabel"
    | OxmMPLSTc _ -> "MplsTc"
    | OxmMetadata t -> 
      (match t.m_mask with
        | None -> "Metadata"
        | Some _ -> "Metadata/mask")
    | OxmIPProto _ -> "IPProto"
    | OxmIPDscp _ -> "IPDscp"
    | OxmIPEcn _ -> "IPEcn"
    | OxmICMPType _ -> "ICMP Type"
    | OxmICMPCode _ -> "ICMP Code"
    | OxmTunnelId t ->
      (match t.m_mask with
        | None -> "Tunnel ID"
        | Some _ -> "Tunnel ID/mask")
    | OxmUDPSrc _ -> "UDPSrc"
    | OxmUDPDst _ -> "UDPDst"
    | OxmSCTPSrc _ -> "SCTPSrc"
    | OxmSCTPDst _ -> "SCTPDst"
    | OxmIPv6Src t ->
      (match t.m_mask with
        | None -> "IPv6Src"
        | Some _ -> "IPv6Src/mask")
    | OxmIPv6Dst t ->
      (match t.m_mask with
        | None -> "IPv6Dst"
        | Some _ -> "IPv6Dst/mask")
    | OxmIPv6FLabel t ->
      (match t.m_mask with
        | None -> "IPv6FlowLabel"
        | Some _ -> "IPv6FlowLabel/mask")
    | OxmICMPv6Type _ -> "ICMPv6Type"
    | OxmICMPv6Code _ -> "IPCMPv6Code"
    | OxmIPv6NDTarget t ->
      (match t.m_mask with
        | None -> "IPv6NeighborDiscoveryTarget"
        | Some _ -> "IPv6NeighborDiscoveryTarget/mask")
    | OxmIPv6NDSll _ -> "IPv6NeighborDiscoverySourceLink"
    | OxmIPv6NDTll _ -> "IPv6NeighborDiscoveryTargetLink"
    | OxmMPLSBos _ -> "MPLSBoS"
    | OxmPBBIsid t ->
      (match t.m_mask with
        | None -> "PBBIsid"
        | Some _ -> "PBBIsid/mask")
    | OxmIPv6ExtHdr t ->
      (match t.m_mask with
        | None -> "IPv6ExtHdr"
        | Some _ -> "IPv6ExtHdr/mask")
    | OxmPBBUCA _ -> "PBBUCA"

  let sizeof (oxm : oxm) : int =
    sizeof_ofp_oxm + field_length oxm

  let sizeof_headers (oxml : oxm list) : int =
    (List.length oxml) * sizeof_ofp_oxm (* OXM Header, without payload*)

  let to_string oxm =
    match oxm with
    | OxmInPort p -> Format.sprintf "InPort = %lu " p
    | OxmInPhyPort p -> Format.sprintf "InPhyPort = %lu " p
    | OxmEthType  e -> Format.sprintf "EthType = %X " e
    | OxmEthDst ethaddr ->
      (match ethaddr.m_mask with
        | None -> Format.sprintf "EthDst = %s" (string_of_mac ethaddr.m_value)
        | Some m -> Format.sprintf "EthDst = %s/%s" (string_of_mac ethaddr.m_value) (string_of_mac m))
    | OxmEthSrc ethaddr ->
      (match ethaddr.m_mask with
        | None -> Format.sprintf "EthSrc = %s" (string_of_mac ethaddr.m_value)
        | Some m -> Format.sprintf "EthSrc = %s/%s" (string_of_mac ethaddr.m_value) (string_of_mac m))
    | OxmVlanVId vid ->
      (match vid.m_mask with
        | None -> Format.sprintf "VlanVId = %u" vid.m_value
        | Some m -> Format.sprintf "VlanVId = %u/%u" vid.m_value m)
    | OxmVlanPcp vid -> Format.sprintf "VlanPcp = %u" vid
    | OxmIP4Src ipaddr ->
      (match ipaddr.m_mask with
        | None -> Format.sprintf "IPSrc = %s" (string_of_ip ipaddr.m_value)
        | Some m -> Format.sprintf "IPSrc = %s/%s" (string_of_ip ipaddr.m_value) (string_of_ip m))
    | OxmIP4Dst ipaddr -> 
      (match ipaddr.m_mask with
        | None -> Format.sprintf "IPDst = %s" (string_of_ip ipaddr.m_value)
        | Some m -> Format.sprintf "IPDst = %s/%s" (string_of_ip ipaddr.m_value) (string_of_ip m))
    | OxmTCPSrc v -> Format.sprintf "TCPSrc = %u" v
    | OxmTCPDst v -> Format.sprintf "TCPDst = %u" v
    | OxmMPLSLabel v -> Format.sprintf "MPLSLabel = %lu" v
    | OxmMPLSTc v -> Format.sprintf "MplsTc = %u" v 
    | OxmMetadata v ->
      (match v.m_mask with
        | None -> Format.sprintf "Metadata = %Lu" v.m_value
        | Some m -> Format.sprintf "Metadata = %Lu/%Lu" v.m_value m)
    | OxmIPProto v -> Format.sprintf "IPProto = %u" v
    | OxmIPDscp v -> Format.sprintf "IPDscp = %u" v
    | OxmIPEcn v -> Format.sprintf "IPEcn = %u" v
    | OxmARPOp v -> Format.sprintf "ARPOp = %u" v
    | OxmARPSpa v ->
      (match v.m_mask with
        | None -> Format.sprintf "ARPSpa = %lu" v.m_value
        | Some m -> Format.sprintf "ARPSpa = %lu/%lu" v.m_value m)
    | OxmARPTpa v ->
      (match v.m_mask with
        | None -> Format.sprintf "ARPTpa = %lu" v.m_value
        | Some m -> Format.sprintf "ARPTpa = %lu/%lu" v.m_value m)
    | OxmARPSha v ->
      (match v.m_mask with
        | None -> Format.sprintf "ARPSha = %Lu" v.m_value
        | Some m -> Format.sprintf "ARPSha = %Lu/%Lu" v.m_value m)
    | OxmARPTha v ->
      (match v.m_mask with
        | None -> Format.sprintf "ARPTha = %Lu" v.m_value
        | Some m -> Format.sprintf "ARPTha = %Lu/%Lu" v.m_value m)
    | OxmICMPType v -> Format.sprintf "ICMPType = %u" v
    | OxmICMPCode v -> Format.sprintf "ICMPCode = %u" v
    | OxmTunnelId v -> 
      (match v.m_mask with
        | None -> Format.sprintf "TunnelID = %Lu" v.m_value
        | Some m -> Format.sprintf "TunnelID = %Lu/%Lu" v.m_value m)
    | OxmUDPSrc v -> Format.sprintf "UDPSrc = %u" v
    | OxmUDPDst v -> Format.sprintf "UDPDst = %u" v
    | OxmSCTPSrc v -> Format.sprintf "SCTPSrc = %u" v
    | OxmSCTPDst v -> Format.sprintf "SCTPDst = %u" v
    | OxmIPv6Src t ->
      (match t.m_mask with
        | None -> Format.sprintf "IPv6Src = %s" (string_of_ipv6 t.m_value)
        | Some m -> Format.sprintf "IPv6Src = %s/%s" (string_of_ipv6 t.m_value) (string_of_ipv6 m))
    | OxmIPv6Dst t ->
      (match t.m_mask with
        | None -> Format.sprintf "IPv6Dst = %s" (string_of_ipv6 t.m_value)
        | Some m -> Format.sprintf "IPv6Dst = %s/%s" (string_of_ipv6 t.m_value) (string_of_ipv6 m))
    | OxmIPv6FLabel t ->
      (match t.m_mask with
        | None -> Format.sprintf "IPv6FlowLabel = %lu" t.m_value
        | Some m -> Format.sprintf "IPv6FlowLabel = %lu/%lu" t.m_value m)
    | OxmICMPv6Type v -> Format.sprintf "ICMPv6Type = %u" v
    | OxmICMPv6Code v -> Format.sprintf "IPCMPv6Code = %u" v
    | OxmIPv6NDTarget t ->
      (match t.m_mask with
        | None -> Format.sprintf "IPv6NeighborDiscoveryTarget = %s" (string_of_ipv6 t.m_value)
        | Some m -> Format.sprintf "IPv6NeighborDiscoveryTarget = %s/%s" (string_of_ipv6 t.m_value) (string_of_ipv6 m))
    | OxmIPv6NDSll v -> Format.sprintf "IPv6NeighborDiscoverySourceLink = %Lu" v
    | OxmIPv6NDTll v -> Format.sprintf "IPv6NeighborDiscoveryTargetLink = %Lu" v
    | OxmMPLSBos v -> Format.sprintf "MPLSBoS = %B" v
    | OxmPBBIsid t ->
      (match t.m_mask with
        | None -> Format.sprintf "PBBIsid = %lu" t.m_value
        | Some m -> Format.sprintf "PBBIsid = %lu/%lu" t.m_value m)
    | OxmIPv6ExtHdr t ->
      (match t.m_mask with
        | None -> Format.sprintf "IPv6ExtHdr = %s" (IPv6ExtHdr.to_string t.m_value)
        | Some m -> Format.sprintf "IPv6ExtHdr = %s/%s" (IPv6ExtHdr.to_string t.m_value) (IPv6ExtHdr.to_string m))
    | OxmPBBUCA v -> Format.sprintf "PBBUCA = %B" v

  let set_ofp_oxm (buf : Cstruct.t) (c : ofp_oxm_class) (f : oxm_ofb_match_fields) (hm : int) (l : int) = 
    let value = (0x7f land (oxm_ofb_match_fields_to_int f)) lsl 1 in
      let value = value lor (0x1 land hm) in
        set_ofp_oxm_oxm_class buf (ofp_oxm_class_to_int c);
        set_ofp_oxm_oxm_field_and_hashmask buf value;
        set_ofp_oxm_oxm_length buf l


  let marshal (buf : Cstruct.t) (oxm : oxm) : int = 
    let l = field_length oxm in
      let ofc = OFPXMC_OPENFLOW_BASIC in
        let buf2 = Cstruct.shift buf sizeof_ofp_oxm in
          match oxm with
            | OxmInPort pid ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IN_PORT 0 l;
              set_ofp_uint32_value buf2 pid;
              sizeof_ofp_oxm + l
            | OxmInPhyPort pid ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IN_PHY_PORT 0 l;
              set_ofp_uint32_value buf2 pid;
              sizeof_ofp_oxm + l
            | OxmEthType ethtype ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ETH_TYPE 0 l;
              set_ofp_uint16_value buf2 ethtype;
              sizeof_ofp_oxm + l
            | OxmEthDst ethaddr ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ETH_DST (match ethaddr.m_mask with None -> 0 | _ -> 1) l;
              set_ofp_uint48_value buf2 ethaddr.m_value;
              begin match ethaddr.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint48_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmEthSrc ethaddr ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ETH_SRC (match ethaddr.m_mask with None -> 0 | _ -> 1) l;
              set_ofp_uint48_value buf2 ethaddr.m_value;
              begin match ethaddr.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint48_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmIP4Src ipaddr ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IPV4_SRC (match ipaddr.m_mask with None -> 0 | _ -> 1) l;
              set_ofp_uint32_value buf2 ipaddr.m_value;
              begin match ipaddr.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint32_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmIP4Dst ipaddr ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IPV4_DST (match ipaddr.m_mask with None -> 0 | _ -> 1) l;
              set_ofp_uint32_value buf2 ipaddr.m_value;
              begin match ipaddr.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint32_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmVlanVId vid ->
              set_ofp_oxm buf ofc OFPXMT_OFB_VLAN_VID (match vid.m_mask with None -> 0 | _ -> 1) l;
              set_ofp_uint16_value buf2 vid.m_value;
              begin match vid.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint16_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmVlanPcp vid ->
              set_ofp_oxm buf ofc OFPXMT_OFB_VLAN_PCP 0 l;
              set_ofp_uint8_value buf2 vid;
              sizeof_ofp_oxm + l
            | OxmMPLSLabel vid ->
              set_ofp_oxm buf ofc OFPXMT_OFB_MPLS_LABEL 0 l;
              set_ofp_uint32_value buf2 vid;
              sizeof_ofp_oxm + l
            | OxmMPLSTc vid ->
              set_ofp_oxm buf ofc OFPXMT_OFB_MPLS_TC 0 l;
              set_ofp_uint8_value buf2 vid;
              sizeof_ofp_oxm + l
            | OxmMetadata meta ->
              set_ofp_oxm buf ofc OFPXMT_OFB_METADATA  (match meta.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint64_value buf2 meta.m_value;
              begin match meta.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint64_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmIPProto ipproto ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IP_PROTO 0 l;
              set_ofp_uint8_value buf2 ipproto;
              sizeof_ofp_oxm + l
            | OxmIPDscp ipdscp ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IP_DSCP 0 l;
              set_ofp_uint8_value buf2 ipdscp;
              sizeof_ofp_oxm + l
            | OxmIPEcn ipecn ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IP_ECN 0 l;
              set_ofp_uint8_value buf2 ipecn;
              sizeof_ofp_oxm + l
            | OxmTCPSrc port ->
              set_ofp_oxm buf ofc OFPXMT_OFB_TCP_SRC 0 l;
              set_ofp_uint16_value buf2 port;
              sizeof_ofp_oxm + l
            | OxmTCPDst port ->
              set_ofp_oxm buf ofc OFPXMT_OFB_TCP_DST 0 l;
              set_ofp_uint16_value buf2 port;
              sizeof_ofp_oxm + l
            | OxmARPOp arp ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ARP_OP 0 l;
              set_ofp_uint16_value buf2 arp;
              sizeof_ofp_oxm + l
            | OxmARPSpa arp ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ARP_SPA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint32_value buf2 arp.m_value;
              begin match arp.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint32_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmARPTpa arp ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ARP_TPA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint32_value buf2 arp.m_value;
              begin match arp.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint32_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmARPSha arp ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ARP_SHA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint48_value buf2 arp.m_value;
              begin match arp.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint48_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmARPTha arp ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ARP_THA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint48_value buf2 arp.m_value;
              begin match arp.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint48_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmICMPType t ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV4_TYPE 0 l;
              set_ofp_uint8_value buf2 t;
              sizeof_ofp_oxm + l
            | OxmICMPCode c->
              set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV4_CODE 0 l;
              set_ofp_uint8_value buf2 c;
              sizeof_ofp_oxm + l
            | OxmTunnelId tun ->
              set_ofp_oxm buf ofc OFPXMT_OFB_TUNNEL_ID  (match tun.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint64_value buf2 tun.m_value;
              begin match tun.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint64_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmUDPSrc port ->
              set_ofp_oxm buf ofc OFPXMT_OFB_UDP_SRC 0 l;
              set_ofp_uint16_value buf2 port;
              sizeof_ofp_oxm + l
            | OxmUDPDst port ->
              set_ofp_oxm buf ofc OFPXMT_OFB_UDP_DST 0 l;
              set_ofp_uint16_value buf2 port;
              sizeof_ofp_oxm + l
            | OxmSCTPSrc port ->
              set_ofp_oxm buf ofc OFPXMT_OFB_SCTP_SRC 0 l;
              set_ofp_uint16_value buf2 port;
              sizeof_ofp_oxm + l
            | OxmSCTPDst port ->
              set_ofp_oxm buf ofc OFPXMT_OFB_SCTP_DST 0 l;
              set_ofp_uint16_value buf2 port;
              sizeof_ofp_oxm + l
            | OxmIPv6Src addr ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_SRC (match addr.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint128_value buf2 addr.m_value;
              begin match addr.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint128_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmIPv6Dst addr ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_DST (match addr.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint128_value buf2 addr.m_value;
              begin match addr.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint128_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmIPv6FLabel label ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_FLABEL (match label.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint32_value buf2 label.m_value;
              begin match label.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint32_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmICMPv6Type typ ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV6_TYPE 0 l;
              set_ofp_uint8_value buf2 typ;
              sizeof_ofp_oxm + l
            | OxmICMPv6Code cod ->
              set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV6_CODE 0 l;
              set_ofp_uint8_value buf2 cod;
              sizeof_ofp_oxm + l
            | OxmIPv6NDTarget addr ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_TARGET (match addr.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint128_value buf2 addr.m_value;
              begin match addr.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint128_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmIPv6NDSll sll ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_SLL 0 l;
              set_ofp_uint48_value buf2 sll;
              sizeof_ofp_oxm + l
            | OxmIPv6NDTll tll ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_TLL 0 l;
              set_ofp_uint48_value buf2 tll;
              sizeof_ofp_oxm + l
            | OxmMPLSBos boS ->
              set_ofp_oxm buf ofc OFPXMT_OFP_MPLS_BOS 0 l;
              (match boS with 
                | true -> set_ofp_uint8_value buf2 1
                | false -> set_ofp_uint8_value buf2 0);
              sizeof_ofp_oxm + l
            | OxmPBBIsid sid ->
              set_ofp_oxm buf ofc OFPXMT_OFB_PBB_ISID (match sid.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint24_value buf2 sid.m_value;
              begin match sid.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint24_value buf3 mask;
                    sizeof_ofp_oxm + l
              end
            | OxmIPv6ExtHdr hdr ->
              set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_EXTHDR (match hdr.m_mask with None -> 0 | _ -> 1)  l;
              set_ofp_uint16_value buf2 (IPv6ExtHdr.marshal hdr.m_value);
              begin match hdr.m_mask with
                | None ->
                  sizeof_ofp_oxm + l
                | Some mask ->
                  let buf3 = Cstruct.shift buf2 (l/2) in
                    set_ofp_uint16_value buf3 (IPv6ExtHdr.marshal mask);
                    sizeof_ofp_oxm + l
              end
            | OxmPBBUCA uca ->
              set_ofp_oxm buf ofc OFPXMT_OFB_PBB_UCA 0 l;
              (match uca with
                | true -> set_ofp_uint8_value buf2 1
                | false -> set_ofp_uint8_value buf2 0);
              sizeof_ofp_oxm + l

  let marshal_header (buf : Cstruct.t) (oxm : oxm) : int = 
  (* Same as marshal, but without the payload *)
    let l = field_length oxm in
      let ofc = OFPXMC_OPENFLOW_BASIC in
        match oxm with
          | OxmInPort _ ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IN_PORT 0 l;
            sizeof_ofp_oxm
          | OxmInPhyPort _ ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IN_PHY_PORT 0 l;
            sizeof_ofp_oxm
          | OxmEthType _ ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ETH_TYPE 0 l;
            sizeof_ofp_oxm
          | OxmEthDst ethaddr ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ETH_DST (match ethaddr.m_mask with None -> 0 | _ -> 1) l;
            sizeof_ofp_oxm
          | OxmEthSrc ethaddr ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ETH_SRC (match ethaddr.m_mask with None -> 0 | _ -> 1) l;
            sizeof_ofp_oxm
          | OxmIP4Src ipaddr ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IPV4_SRC (match ipaddr.m_mask with None -> 0 | _ -> 1) l;
            sizeof_ofp_oxm
          | OxmIP4Dst ipaddr ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IPV4_DST (match ipaddr.m_mask with None -> 0 | _ -> 1) l;
            sizeof_ofp_oxm
          | OxmVlanVId vid ->
            set_ofp_oxm buf ofc OFPXMT_OFB_VLAN_VID (match vid.m_mask with None -> 0 | _ -> 1) l;
            sizeof_ofp_oxm
          | OxmVlanPcp vid ->
            set_ofp_oxm buf ofc OFPXMT_OFB_VLAN_PCP 0 l;
            sizeof_ofp_oxm
          | OxmMPLSLabel vid ->
            set_ofp_oxm buf ofc OFPXMT_OFB_MPLS_LABEL 0 l;
            sizeof_ofp_oxm
          | OxmMPLSTc vid ->
            set_ofp_oxm buf ofc OFPXMT_OFB_MPLS_TC 0 l;
            sizeof_ofp_oxm
          | OxmMetadata meta ->
            set_ofp_oxm buf ofc OFPXMT_OFB_METADATA  (match meta.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmIPProto ipproto ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IP_PROTO 0 l;
            sizeof_ofp_oxm
          | OxmIPDscp ipdscp ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IP_DSCP 0 l;
            sizeof_ofp_oxm
          | OxmIPEcn ipecn ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IP_ECN 0 l;
            sizeof_ofp_oxm
          | OxmTCPSrc port ->
            set_ofp_oxm buf ofc OFPXMT_OFB_TCP_SRC 0 l;
            sizeof_ofp_oxm
          | OxmTCPDst port ->
            set_ofp_oxm buf ofc OFPXMT_OFB_TCP_DST 0 l;
            sizeof_ofp_oxm
          | OxmARPOp arp ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ARP_OP 0 l;
            sizeof_ofp_oxm
          | OxmARPSpa arp ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ARP_SPA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmARPTpa arp ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ARP_TPA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmARPSha arp ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ARP_SHA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmARPTha arp ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ARP_THA  (match arp.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmICMPType t ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV4_TYPE 0 l;
            sizeof_ofp_oxm
          | OxmICMPCode c->
            set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV4_CODE 0 l;
            sizeof_ofp_oxm
          | OxmTunnelId tun ->
            set_ofp_oxm buf ofc OFPXMT_OFB_TUNNEL_ID  (match tun.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmUDPSrc port ->
            set_ofp_oxm buf ofc OFPXMT_OFB_UDP_SRC 0 l;
            sizeof_ofp_oxm
          | OxmUDPDst port ->
            set_ofp_oxm buf ofc OFPXMT_OFB_UDP_DST 0 l;
            sizeof_ofp_oxm
          | OxmSCTPSrc port ->
            set_ofp_oxm buf ofc OFPXMT_OFB_SCTP_SRC 0 l;
            sizeof_ofp_oxm
          | OxmSCTPDst port ->
            set_ofp_oxm buf ofc OFPXMT_OFB_SCTP_DST 0 l;
            sizeof_ofp_oxm
          | OxmIPv6Src addr ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_SRC (match addr.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmIPv6Dst addr ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_DST (match addr.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmIPv6FLabel label ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_FLABEL (match label.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmICMPv6Type typ ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV6_TYPE 0 l;
            sizeof_ofp_oxm
          | OxmICMPv6Code cod ->
            set_ofp_oxm buf ofc OFPXMT_OFB_ICMPV6_CODE 0 l;
            sizeof_ofp_oxm
          | OxmIPv6NDTarget addr ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_TARGET (match addr.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmIPv6NDSll sll ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_SLL 0 l;
            sizeof_ofp_oxm
          | OxmIPv6NDTll tll ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_ND_TLL 0 l;
            sizeof_ofp_oxm
          | OxmMPLSBos boS ->
            set_ofp_oxm buf ofc OFPXMT_OFP_MPLS_BOS 0 l;
            sizeof_ofp_oxm
          | OxmPBBIsid sid ->
            set_ofp_oxm buf ofc OFPXMT_OFB_PBB_ISID (match sid.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmIPv6ExtHdr hdr ->
            set_ofp_oxm buf ofc OFPXMT_OFB_IPV6_EXTHDR (match hdr.m_mask with None -> 0 | _ -> 1)  l;
            sizeof_ofp_oxm
          | OxmPBBUCA _ ->
            set_ofp_oxm buf ofc OFPXMT_OFB_PBB_UCA 0 l;
            sizeof_ofp_oxm



  let parse (bits : Cstruct.t) : oxm * Cstruct.t =
    (* printf "class= %d\n" (get_ofp_oxm_oxm_class bits); *)
    (* let c = match int_to_ofp_oxm_class (get_ofp_oxm_oxm_class bits) with *)
    (*   | Some n -> n *)
    (*   | None ->  *)
    (*     raise (Unparsable (sprintf "malformed class in oxm")) in *)
    (* TODO: assert c is OFPXMC_OPENFLOW_BASIC *)
    let value = get_ofp_oxm_oxm_field_and_hashmask bits in
    let f = match int_to_oxm_ofb_match_fields (value lsr 1) with
      | Some n -> n
      | None -> 
        raise (Unparsable (sprintf "malformed field in oxm %d" (value lsr 1))) in
    let hm = value land 0x1 in
    let oxm_length = get_ofp_oxm_oxm_length bits in
    let bits = Cstruct.shift bits sizeof_ofp_oxm in
    let bits2 = Cstruct.shift bits oxm_length in
    match f with
      | OFPXMT_OFB_IN_PORT ->
        let pid = get_ofp_uint32_value bits in
        (OxmInPort pid, bits2)
      | OFPXMT_OFB_IN_PHY_PORT ->
        let pid = get_ofp_uint32_value bits in
        (OxmInPhyPort pid, bits2)
      | OFPXMT_OFB_METADATA ->
        let value = get_ofp_uint64_value bits in
        if hm = 1 then
          let bits = Cstruct.shift bits 8 in
          let mask = get_ofp_uint64_value bits in
          (OxmMetadata {m_value = value; m_mask = (Some mask)}, bits2)
        else
          (OxmMetadata {m_value = value; m_mask = None}, bits2)
      | OFPXMT_OFB_TUNNEL_ID ->
        let value = get_ofp_uint64_value bits in
        if hm = 1 then
          let bits = Cstruct.shift bits 8 in
          let mask = get_ofp_uint64_value bits in
          (OxmTunnelId {m_value = value; m_mask = (Some mask)}, bits2)
        else
          (OxmTunnelId {m_value = value; m_mask = None}, bits2)
      (* Ethernet destination address. *)
      | OFPXMT_OFB_ETH_DST ->
	let value = get_ofp_uint48_value bits in
	if hm = 1 then
	  let bits = Cstruct.shift bits 6 in
	  let mask = get_ofp_uint48_value bits in
	  (OxmEthDst {m_value = value; m_mask = (Some mask)}, bits2)
	else
	  (OxmEthDst {m_value = value; m_mask = None}, bits2)
      (* Ethernet source address. *)
      | OFPXMT_OFB_ETH_SRC ->
	let value = get_ofp_uint48_value bits in
	if hm = 1 then
	  let bits = Cstruct.shift bits 6 in
	  let mask = get_ofp_uint48_value bits in
	  (OxmEthSrc {m_value = value; m_mask = (Some mask)}, bits2)
	else
	  (OxmEthSrc {m_value = value; m_mask = None}, bits2)
      (* Ethernet frame type. *)
      | OFPXMT_OFB_ETH_TYPE ->
	let value = get_ofp_uint16_value bits in
	  (OxmEthType value, bits2)
      (* IP protocol. *)
      | OFPXMT_OFB_IP_PROTO ->
	let value = get_ofp_uint8_value bits in
	  (OxmIPProto value, bits2)
      (* IP DSCP (6 bits in ToS field). *)
      | OFPXMT_OFB_IP_DSCP ->
	let value = get_ofp_uint8_value bits in
	  (OxmIPDscp (value land 63), bits2)
      (* IP ECN (2 bits in ToS field). *)
      |  OFPXMT_OFB_IP_ECN ->
	let value = get_ofp_uint8_value bits in
	  (OxmIPEcn (value land 3), bits2)
      (* IPv4 source address. *)
      | OFPXMT_OFB_IPV4_SRC ->
	let value = get_ofp_uint32_value bits in
	if hm = 1 then
	  let bits = Cstruct.shift bits 4 in
	  let mask = get_ofp_uint32_value bits in
	  (OxmIP4Src {m_value = value; m_mask = (Some mask)}, bits2)
	else
	  (OxmIP4Src {m_value = value; m_mask = None}, bits2)
      (* IPv4 destination address. *)
      | OFPXMT_OFB_IPV4_DST ->
	let value = get_ofp_uint32_value bits in
	if hm = 1 then
	  let bits = Cstruct.shift bits 4 in
	  let mask = get_ofp_uint32_value bits in
	  (OxmIP4Dst {m_value = value; m_mask = (Some mask)}, bits2)
	else
	  (OxmIP4Dst {m_value = value; m_mask = None}, bits2)
      (* ARP opcode. *)
      | OFPXMT_OFB_ARP_OP ->
	let value = get_ofp_uint16_value bits in
	  (OxmARPOp value, bits2)
      (* ARP source IPv4 address. *)
      | OFPXMT_OFB_ARP_SPA ->
	let value = get_ofp_uint32_value bits in
	if hm = 1 then
	  let bits = Cstruct.shift bits 4 in
	  let mask = get_ofp_uint32_value bits in
	  (OxmARPSpa {m_value = value; m_mask = (Some mask)}, bits2)
	else
	  (OxmARPSpa {m_value = value; m_mask = None}, bits2)
      (* ARP target IPv4 address. *)
      | OFPXMT_OFB_ARP_TPA ->
	let value = get_ofp_uint32_value bits in
	if hm = 1 then
	  let bits = Cstruct.shift bits 4 in
	  let mask = get_ofp_uint32_value bits in
	  (OxmARPTpa {m_value = value; m_mask = (Some mask)}, bits2)
	else
	  (OxmARPTpa {m_value = value; m_mask = None}, bits2)
      (* ARP source hardware address. *)
      | OFPXMT_OFB_ARP_SHA ->
	let value = get_ofp_uint48_value bits in
	if hm = 1 then
	  let bits = Cstruct.shift bits 6 in
	  let mask = get_ofp_uint48_value bits in
	  (OxmARPSha {m_value = value; m_mask = (Some mask)}, bits2)
	else
	  (OxmARPSha {m_value = value; m_mask = None}, bits2)
      (* ARP target hardware address. *)
      | OFPXMT_OFB_ARP_THA ->
	let value = get_ofp_uint48_value bits in
	if hm = 1 then
	  let bits = Cstruct.shift bits 6 in
	  let mask = get_ofp_uint48_value bits in
	  (OxmARPTha {m_value = value; m_mask = (Some mask)}, bits2)
	else
	  (OxmARPTha {m_value = value; m_mask = None}, bits2)
      (* ICMP Type *)
      | OFPXMT_OFB_ICMPV4_TYPE ->
	let value = get_ofp_uint8_value bits in
	  (OxmICMPType value, bits2)
      (* ICMP code. *)
      |   OFPXMT_OFB_ICMPV4_CODE ->
	let value = get_ofp_uint8_value bits in
	  (OxmICMPCode value, bits2)
      | OFPXMT_OFB_TCP_DST ->
    let value = get_ofp_uint16_value bits in
	  (OxmTCPDst value, bits2)
      | OFPXMT_OFB_TCP_SRC ->
    let value = get_ofp_uint16_value bits in
	  (OxmTCPSrc value, bits2)
      | OFPXMT_OFB_MPLS_LABEL ->
    let value = get_ofp_uint32_value bits in
	  (OxmMPLSLabel value, bits2)
      | OFPXMT_OFB_VLAN_PCP ->
    let value = get_ofp_uint8_value bits in
	  (OxmVlanPcp value, bits2)
      | OFPXMT_OFB_VLAN_VID ->
    let value = get_ofp_uint16_value bits in
	if hm = 1 then
	  let bits = Cstruct.shift bits 2 in
	  let mask = get_ofp_uint16_value bits in
	  (OxmVlanVId {m_value = value; m_mask = (Some mask)}, bits2)
	else
	  (OxmVlanVId {m_value = value; m_mask = None}, bits2)
      | OFPXMT_OFB_MPLS_TC ->
    let value = get_ofp_uint8_value bits in
	  (OxmMPLSTc value, bits2)
      | OFPXMT_OFB_UDP_SRC ->
    let value = get_ofp_uint16_value bits in
      (OxmUDPSrc value, bits2)
      | OFPXMT_OFB_UDP_DST ->
    let value = get_ofp_uint16_value bits in
      (OxmUDPDst value, bits2)
      | OFPXMT_OFB_SCTP_SRC ->
    let value = get_ofp_uint16_value bits in
      (OxmSCTPSrc value, bits2)
      | OFPXMT_OFB_SCTP_DST ->
    let value = get_ofp_uint16_value bits in
      (OxmSCTPDst value, bits2)
      | OFPXMT_OFB_IPV6_SRC ->
    let value = get_ofp_uint128_value bits in
    if hm = 1 then
      let bits = Cstruct.shift bits 16 in
      let mask = get_ofp_uint128_value bits in
      (OxmIPv6Src {m_value = value; m_mask = (Some mask)}, bits2)
    else
      (OxmIPv6Src {m_value = value; m_mask = None}, bits2)
      | OFPXMT_OFB_IPV6_DST ->
    let value = get_ofp_uint128_value bits in
    if hm = 1 then
      let bits = Cstruct.shift bits 16 in
      let mask = get_ofp_uint128_value bits in
      (OxmIPv6Dst {m_value = value; m_mask = (Some mask)}, bits2)
    else
      (OxmIPv6Dst {m_value = value; m_mask = None}, bits2)
      | OFPXMT_OFB_IPV6_FLABEL ->
    let value = get_ofp_uint32_value bits in
    if hm = 1 then
      let bits = Cstruct.shift bits 4 in
      let mask = get_ofp_uint32_value bits in
      (OxmIPv6FLabel {m_value = value; m_mask = (Some mask)}, bits2)
    else
      (OxmIPv6FLabel {m_value = value; m_mask = None}, bits2)
      | OFPXMT_OFB_ICMPV6_TYPE ->
    let value = get_ofp_uint8_value bits in
      (OxmICMPv6Type value, bits2)
      | OFPXMT_OFB_ICMPV6_CODE ->
    let value = get_ofp_uint8_value bits in
      (OxmICMPv6Code value, bits2)
      | OFPXMT_OFB_IPV6_ND_TARGET ->
    let value = get_ofp_uint128_value bits in
    if hm = 1 then
      let bits = Cstruct.shift bits 16 in
      let mask = get_ofp_uint128_value bits in
      (OxmIPv6NDTarget {m_value = value; m_mask = (Some mask)}, bits2)
    else
      (OxmIPv6NDTarget {m_value = value; m_mask = None}, bits2)
      | OFPXMT_OFB_IPV6_ND_SLL ->
    let value = get_ofp_uint48_value bits in
      (OxmIPv6NDSll value, bits2)
      | OFPXMT_OFB_IPV6_ND_TLL ->
    let value = get_ofp_uint48_value bits in
      (OxmIPv6NDTll value, bits2)
      | OFPXMT_OFP_MPLS_BOS ->
    let value = get_ofp_uint8_value bits in
      (OxmMPLSBos ((value land 1) = 1), bits2)
      | OFPXMT_OFB_PBB_ISID ->
    let value = get_ofp_uint24_value bits in
    if hm = 1 then
      let bits = Cstruct.shift bits 3 in
      let mask = get_ofp_uint24_value bits in
      (OxmPBBIsid {m_value = value; m_mask = (Some mask)}, bits2)
    else
      (OxmPBBIsid {m_value = value; m_mask = None}, bits2)
      | OFPXMT_OFB_IPV6_EXTHDR ->
    let value = IPv6ExtHdr.parse (get_ofp_uint16_value bits) in
    if hm = 1 then
      let bits = Cstruct.shift bits 2 in
      let mask = IPv6ExtHdr.parse (get_ofp_uint16_value bits) in
      (OxmIPv6ExtHdr {m_value = value; m_mask = (Some mask)}, bits2)
    else
      (OxmIPv6ExtHdr {m_value = value; m_mask = None}, bits2)
      | OFPXMT_OFB_PBB_UCA ->
    let value = get_ofp_uint8_value bits in
      (OxmPBBUCA ((value land 1) = 1), bits2)

  let parse_header (bits : Cstruct.t) : oxm * Cstruct.t =
    (* parse Oxm header function for TableFeatureProp. Similar to parse, but without
       parsing the payload *)
    let value = get_ofp_oxm_oxm_field_and_hashmask bits in
    let f = match int_to_oxm_ofb_match_fields (value lsr 1) with
      | Some n -> n
      | None -> raise (Unparsable (sprintf "malformed field in oxm %d" (value lsr 1))) in
    let hm = value land 0x1 in
    let bits2 = Cstruct.shift bits sizeof_ofp_oxm in
    match f with
      | OFPXMT_OFB_IN_PORT ->
        (OxmInPort 0l, bits2)
      | OFPXMT_OFB_IN_PHY_PORT ->
        (OxmInPhyPort 0l, bits2)
      | OFPXMT_OFB_METADATA ->
        if hm = 1 then
          (OxmMetadata {m_value = 0L; m_mask = (Some 0L)}, bits2)
        else
          (OxmMetadata {m_value = 0L; m_mask = None}, bits2)
      | OFPXMT_OFB_TUNNEL_ID ->
        if hm = 1 then
          (OxmTunnelId {m_value = 0L; m_mask = (Some 0L)}, bits2)
        else
          (OxmTunnelId {m_value = 0L; m_mask = None}, bits2)
      (* Ethernet destination address. *)
      | OFPXMT_OFB_ETH_DST ->
        if hm = 1 then
          (OxmEthDst {m_value = 0L; m_mask = (Some 0L)}, bits2)
        else
          (OxmEthDst {m_value = 0L; m_mask = None}, bits2)
      (* Ethernet source address. *)
      | OFPXMT_OFB_ETH_SRC ->
        if hm = 1 then
          (OxmEthSrc {m_value = 0L; m_mask = (Some 0L)}, bits2)
        else
          (OxmEthSrc {m_value = 0L; m_mask = None}, bits2)
       (* Ethernet frame type. *)
      | OFPXMT_OFB_ETH_TYPE ->
          (OxmEthType 0, bits2)
       (* IP protocol. *)
      | OFPXMT_OFB_IP_PROTO ->
          (OxmIPProto 0, bits2)
      (* IP DSCP (6 bits in ToS field). *)
      | OFPXMT_OFB_IP_DSCP ->
          (OxmIPDscp (0 land 63), bits2)
      (* IP ECN (2 bits in ToS field). *)
      |  OFPXMT_OFB_IP_ECN ->
          (OxmIPEcn (0 land 3), bits2)
      (* IPv4 source address. *)
      | OFPXMT_OFB_IPV4_SRC ->
        if hm = 1 then
          (OxmIP4Src {m_value = 0l; m_mask = (Some 0l)}, bits2)
        else
          (OxmIP4Src {m_value = 0l; m_mask = None}, bits2)
      (* IPv4 destination address. *)
      | OFPXMT_OFB_IPV4_DST ->
        if hm = 1 then
          (OxmIP4Dst {m_value = 0l; m_mask = (Some 0l)}, bits2)
        else
          (OxmIP4Dst {m_value = 0l; m_mask = None}, bits2)
      (* ARP opcode. *)
      | OFPXMT_OFB_ARP_OP ->
        (OxmARPOp 0, bits2)
      (* ARP source IPv4 address. *)
      | OFPXMT_OFB_ARP_SPA ->
        if hm = 1 then
          (OxmARPSpa {m_value = 0l; m_mask = (Some 0l)}, bits2)
        else
          (OxmARPSpa {m_value = 0l; m_mask = None}, bits2)
      (* ARP target IPv4 address. *)
      | OFPXMT_OFB_ARP_TPA ->
        if hm = 1 then
          (OxmARPTpa {m_value = 0l; m_mask = (Some 0l)}, bits2)
        else
          (OxmARPTpa {m_value = 0l; m_mask = None}, bits2)
      (* ARP source hardware address. *)
      | OFPXMT_OFB_ARP_SHA ->
        if hm = 1 then
          (OxmARPSha {m_value = 0L; m_mask = (Some 0L)}, bits2)
        else
          (OxmARPSha {m_value = 0L; m_mask = None}, bits2)
    (* ARP target hardware address. *)
      | OFPXMT_OFB_ARP_THA ->
        if hm = 1 then
          (OxmARPTha {m_value = 0L; m_mask = (Some 0L)}, bits2)
        else
          (OxmARPTha {m_value = 0L; m_mask = None}, bits2)
      (* ICMP Type *)
      | OFPXMT_OFB_ICMPV4_TYPE ->
          (OxmICMPType 0, bits2)
      (* ICMP code. *)
      |   OFPXMT_OFB_ICMPV4_CODE ->
          (OxmICMPCode 0, bits2)
      | OFPXMT_OFB_TCP_DST ->
          (OxmTCPDst 0, bits2)
      | OFPXMT_OFB_TCP_SRC ->
          (OxmTCPSrc 0, bits2)
      | OFPXMT_OFB_MPLS_LABEL ->
          (OxmMPLSLabel 0l, bits2)
      | OFPXMT_OFB_VLAN_PCP ->
          (OxmVlanPcp 0, bits2)
      | OFPXMT_OFB_VLAN_VID ->
        if hm = 1 then
          (OxmVlanVId {m_value = 0; m_mask = (Some 0)}, bits2)
        else
          (OxmVlanVId {m_value = 0; m_mask = None}, bits2)
      | OFPXMT_OFB_MPLS_TC ->
          (OxmMPLSTc 0, bits2)
      | OFPXMT_OFB_UDP_SRC ->
    (OxmUDPSrc 0, bits2)
    | OFPXMT_OFB_UDP_DST ->
    (OxmUDPDst 0, bits2)
    | OFPXMT_OFB_SCTP_SRC ->
    (OxmSCTPSrc 0, bits2)
    | OFPXMT_OFB_SCTP_DST ->
    (OxmSCTPDst 0, bits2)
    | OFPXMT_OFB_IPV6_SRC ->
      if hm = 1 then
    (OxmIPv6Src {m_value = (0L,0L); m_mask = (Some (0L,0L))}, bits2)
      else
    (OxmIPv6Src {m_value = (0L,0L); m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_DST ->
      if hm = 1 then
    (OxmIPv6Dst {m_value = (0L,0L); m_mask = (Some (0L,0L))}, bits2)
      else
    (OxmIPv6Dst {m_value = (0L,0L); m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_FLABEL ->
      if hm = 1 then
    (OxmIPv6FLabel {m_value = 0l; m_mask = (Some 0l)}, bits2)
      else
    (OxmIPv6FLabel {m_value = 0l; m_mask = None}, bits2)
    | OFPXMT_OFB_ICMPV6_TYPE ->
    (OxmICMPv6Type 0, bits2)
    | OFPXMT_OFB_ICMPV6_CODE ->
    (OxmICMPv6Code 0, bits2)
    | OFPXMT_OFB_IPV6_ND_TARGET ->
      if hm = 1 then
    (OxmIPv6NDTarget {m_value = (0L,0L); m_mask = (Some (0L,0L))}, bits2)
      else
    (OxmIPv6NDTarget {m_value = (0L,0L); m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_ND_SLL ->
    (OxmIPv6NDSll 0L, bits2)
    | OFPXMT_OFB_IPV6_ND_TLL ->
    (OxmIPv6NDTll 0L, bits2)
    | OFPXMT_OFP_MPLS_BOS ->
    (OxmMPLSBos false, bits2)
    | OFPXMT_OFB_PBB_ISID ->
      if hm = 1 then
    (OxmPBBIsid {m_value = 0l; m_mask = (Some 0l)}, bits2)
      else
    (OxmPBBIsid {m_value = 0l; m_mask = None}, bits2)
    | OFPXMT_OFB_IPV6_EXTHDR ->
      let nul = {noext = false; esp = false; auth = false; dest = false; frac = false; router = false; hop = false; unrep = false; unseq = false } in
      if hm = 1 then
    (OxmIPv6ExtHdr {m_value = nul; m_mask = (Some nul)}, bits2)
      else
    (OxmIPv6ExtHdr {m_value = nul; m_mask = None}, bits2)
    | OFPXMT_OFB_PBB_UCA ->
    (OxmPBBUCA false, bits2)

  let rec parse_headers (bits : Cstruct.t) : oxmMatch*Cstruct.t = 
    if Cstruct.len bits < sizeof_ofp_oxm then ([], bits)
    else let field, bits2 = parse_header bits in
    let fields, bits3 = parse_headers bits2 in    
    (List.append [field] fields, bits3)

end

module OfpMatch = struct

  cstruct ofp_match {
    uint16_t typ;          
    uint16_t length
  } as big_endian

  type t = oxmMatch

  let sizeof (om : oxmMatch) : int =
    let n = sizeof_ofp_match + sum (map Oxm.sizeof om) in
    pad_to_64bits n

  let to_string om = 
    "[ " ^ (String.concat "; " (map Oxm.to_string om)) ^ " ]"

  let marshal (buf : Cstruct.t) (om : oxmMatch) : int =
    let size = sizeof om in
    set_ofp_match_typ buf 1; (* OXPMT_OXM *)
    set_ofp_match_length buf (sizeof_ofp_match + sum (map Oxm.sizeof om)); (* Length of ofp_match (excluding padding) *)
    let buf = Cstruct.shift buf sizeof_ofp_match in
    let oxm_size = marshal_fields buf om Oxm.marshal in
    let pad = size - (sizeof_ofp_match + oxm_size) in
    if pad > 0 then
      let buf = Cstruct.shift buf oxm_size in
      let _ = pad_with_zeros buf pad in
      size
    else size

  let rec parse_fields (bits : Cstruct.t) : oxmMatch * Cstruct.t =
    if Cstruct.len bits <= sizeof_ofp_oxm then ([], bits)
    else let field, bits2 = Oxm.parse bits in
    let fields, bits3 = parse_fields bits2 in
    (List.append [field] fields, bits3)

  let parse (bits : Cstruct.t) : oxmMatch * Cstruct.t =
    let length = get_ofp_match_length bits in
    let oxm_bits = Cstruct.sub bits sizeof_ofp_match (length - sizeof_ofp_match) in
    let fields, _ = parse_fields oxm_bits in
    let bits = Cstruct.shift bits (pad_to_64bits length) in
    (fields, bits)

end 

module PseudoPort = struct
  type t = pseudoPort

  cenum ofp_port_no {
    (* Maximum number of physical and logical switch ports. *)
    OFPP_MAX        = 0xffffff00l;

    (* Reserved OpenFlow Port (fake output "ports"). *)
    OFPP_IN_PORT    = 0xfffffff8l; (* Send the packet out the input port. This
                                      reserved port must be explicitly used
                                      in order to send back out of the input
                                      port.*)
    OFPP_TABLE      = 0xfffffff9l; (* Submit the packet to the first flow table
                                      NB: This destination port can only be
                                      used in packet-out messages. *)
    OFPP_NORMAL     = 0xfffffffal; (* Process with normal L2/L3 switching. *)
    OFPP_FLOOD      = 0xfffffffbl; (* All physical ports in VLAN, except input
                                      port and those blocked or link down. *)
    OFPP_ALL        = 0xfffffffcl; (* All physical ports except input port. *)
    OFPP_CONTROLLER = 0xfffffffdl; (* Send to controller. *)
    OFPP_LOCAL      = 0xfffffffel; (* Local openflow "port". *)
    OFPP_ANY        = 0xffffffffl  (* Wildcard port used only for flow mod
                                     (delete) and flow stats requests. Selects
                                     all flows regardless of output port
                                     (including flows with no output port). *)
  } as uint32_t

  let size_of _ = 4

  let to_string (t : t) = 
   match t with
    | PhysicalPort p -> sprintf "PhysicalPort = %lu" p
    | InPort -> "InPort"
    | Table -> "Table"
    | Normal -> "Normal"
    | Flood -> "Flood"
    | AllPorts -> "AllPorts"
    | Controller n -> sprintf "Controller<%d bytes>" n
    | Local -> "Local"
    | Any -> "Any"

  let marshal (t : t) : int32 = match t with
    | PhysicalPort(p) -> p
    | InPort -> ofp_port_no_to_int OFPP_IN_PORT
    | Table -> ofp_port_no_to_int OFPP_TABLE
    | Normal -> ofp_port_no_to_int OFPP_NORMAL
    | Flood -> ofp_port_no_to_int  OFPP_FLOOD
    | AllPorts -> ofp_port_no_to_int OFPP_ALL
    | Controller(_) -> ofp_port_no_to_int  OFPP_CONTROLLER
    | Local -> ofp_port_no_to_int  OFPP_LOCAL
    | Any -> ofp_port_no_to_int  OFPP_ANY

  let make ofp_port_no_code len =
    match int_to_ofp_port_no ofp_port_no_code with
      | Some OFPP_IN_PORT -> InPort
      | Some OFPP_TABLE -> Table
      | Some OFPP_NORMAL -> Normal
      | Some OFPP_FLOOD -> Flood
      | Some OFPP_ALL -> AllPorts
      | Some OFPP_CONTROLLER -> Controller len
      | Some OFPP_LOCAL -> Local
      | Some OFPP_ANY -> Any
      | _ ->
        if compare_uint32 ofp_port_no_code (ofp_port_no_to_int OFPP_MAX) then
          PhysicalPort ofp_port_no_code
        else
          raise
            (Unparsable (sprintf "unsupported port number (%lu)" ofp_port_no_code))

end


module Action = struct

  cstruct ofp_action_output {
      uint16_t typ;                   (* OFPAT_OUTPUT. *)
      uint16_t len;                   (* Length is 16. *)
      uint32_t port;                  (* Output port. *)
      uint16_t max_len;               (* Max length to send to controller. *)
      uint8_t pad0;                   (* Pad to 64 bits. *)
      uint8_t pad1;                   (* Pad to 64 bits. *)
      uint8_t pad2;                   (* Pad to 64 bits. *)
      uint8_t pad3;                   (* Pad to 64 bits. *)
      uint8_t pad4;                   (* Pad to 64 bits. *)
      uint8_t pad5                    (* Pad to 64 bits. *)
  } as big_endian

  (* Action structure for OFPAT_GROUP. *)
  cstruct ofp_action_group {
    uint16_t typ;                   (* OFPAT_GROUP. *)
    uint16_t len;                   (* Length is 8. *)
    uint32_t group_id               (* Group identifier. *)
  } as big_endian

  (* Generic action header. Used for POP_VLAN *)
  cstruct ofp_action_header {
    uint16_t typ;                   (* POP_VLAN. *)
    uint16_t len;                   (* Length is 8. *)
    uint8_t pad;
    uint8_t pad1;
    uint8_t pad2;
    uint8_t pad3
  } as big_endian

  (* Action structure for POP_MPLS *)
  cstruct ofp_action_pop_mpls {
    uint16_t typ;                   (* POP_VLAN. *)
    uint16_t len;                   (* Length is 8. *)
    uint16_t ethertype;
    uint8_t pad0;
    uint8_t pad1
  } as big_endian

  (* Action structure for SET_NW_TTL *)
  cstruct ofp_action_nw_ttl {
    uint16_t typ;                   (* SET_NW_TTL. *)
    uint16_t len;                   (* Length is 8. *)
    uint8_t nw_ttl;
    uint8_t pad;
    uint8_t pad1;
    uint8_t pad2
  } as big_endian

  (* Action structure for SET_MPLS_TTL *)
  cstruct ofp_action_mpls_ttl {
    uint16_t typ;                   (* SET_MPLS_TTL. *)
    uint16_t len;                   (* Length is 8. *)
    uint8_t mpls_ttl;
    uint8_t pad[3];
  } as big_endian

  (* Action structure for *_PUSH *)
  cstruct ofp_action_push {
    uint16_t typ;                   (* OFPAT_PUSH_VLAN/MPLS/PBB *)
    uint16_t len;                   (* Length is 8. *)
    uint16_t ethertype;
    uint8_t pad0;
    uint8_t pad1
  } as big_endian

  (* Action structure for OFPAT_SET_FIELD. *)
  cstruct ofp_action_set_field {
      uint16_t typ;                  (* OFPAT_SET_FIELD. *)
      uint16_t len                   (* Length is padded to 64 bits. *)

  } as big_endian

  (* Action structure for SET_QUEUE *)
  cstruct ofp_action_set_queue {
     uint16_t typ;                   (* OFPAT_SET_QUEUE*)
     uint16_t len;                   (* Length is 8. *)
     uint32_t queue_id
  } as big_endian

  cstruct ofp_action_experimenter { 
     uint16_t typ;
     uint16_t len;
     uint32_t experimenter
  } as big_endian

  cenum ofp_action_type {
    OFPAT_OUTPUT       = 0;  (* Output to switch port. *)
    OFPAT_COPY_TTL_OUT = 11; (* Copy TTL "outwards" -- from next-to-outermost
                                to outermost *)
    OFPAT_COPY_TTL_IN  = 12; (* Copy TTL "inwards" -- from outermost to
                               next-to-outermost *)
    OFPAT_SET_MPLS_TTL = 15; (* MPLS TTL *)
    OFPAT_DEC_MPLS_TTL = 16; (* Decrement MPLS TTL *)

    OFPAT_PUSH_VLAN    = 17; (* Push a new VLAN tag *)
    OFPAT_POP_VLAN     = 18; (* Pop the outer VLAN tag *)
    OFPAT_PUSH_MPLS    = 19; (* Push a new MPLS tag *)
    OFPAT_POP_MPLS     = 20; (* Pop the outer MPLS tag *)
    OFPAT_SET_QUEUE    = 21; (* Set queue id when outputting to a port *)
    OFPAT_GROUP        = 22; (* Apply group. *)
    OFPAT_SET_NW_TTL   = 23; (* IP TTL. *)
    OFPAT_DEC_NW_TTL   = 24; (* Decrement IP TTL. *)
    OFPAT_SET_FIELD    = 25; (* Set a header field using OXM TLV format. *)
    OFPAT_PUSH_PBB     = 26; (* Push a new PBB service tag (I-TAG) *)
    OFPAT_POP_PBB      = 27; (* Pop the outer PBB service tag (I-TAG) *)
    OFPAT_EXPERIMENTER = 0xffff
  } as uint16_t

  type sequence = OpenFlow0x05_Core.actionSequence

  type t = action

  let sizeof (act : action) : int = match act with
    | Output _ -> sizeof_ofp_action_output
    | Group _ -> sizeof_ofp_action_group
    | PopVlan -> sizeof_ofp_action_header
    | PushVlan -> sizeof_ofp_action_push
    | PopMpls -> sizeof_ofp_action_pop_mpls
    | PushMpls -> sizeof_ofp_action_push
    | SetField oxm -> pad_to_64bits (sizeof_ofp_action_set_field + Oxm.sizeof oxm)
    | CopyTtlOut -> sizeof_ofp_action_header
    | CopyTtlIn -> sizeof_ofp_action_header
    | SetNwTtl _ -> sizeof_ofp_action_nw_ttl
    | DecNwTtl -> sizeof_ofp_action_header
    | PushPbb -> sizeof_ofp_action_push
    | PopPbb -> sizeof_ofp_action_header
    | SetMplsTtl _ -> sizeof_ofp_action_push
    | DecMplsTtl -> sizeof_ofp_action_header
    | SetQueue _ -> sizeof_ofp_action_set_queue
    | Experimenter _ -> sizeof_ofp_action_experimenter

  let to_type t : actionTyp = 
    match (int_to_ofp_action_type t) with
      | Some OFPAT_OUTPUT -> Output
      | Some OFPAT_COPY_TTL_OUT -> CopyTTLOut
      | Some OFPAT_COPY_TTL_IN -> CopyTTLIn
      | Some OFPAT_SET_MPLS_TTL -> SetMPLSTTL
      | Some OFPAT_DEC_MPLS_TTL -> DecMPLSTTL
      | Some OFPAT_PUSH_VLAN -> PushVLAN
      | Some OFPAT_POP_VLAN -> PopVLAN
      | Some OFPAT_PUSH_MPLS -> PushMPLS
      | Some OFPAT_POP_MPLS -> PopMPLS
      | Some OFPAT_SET_QUEUE -> SetQueue
      | Some OFPAT_GROUP -> Group
      | Some OFPAT_SET_NW_TTL -> SetNWTTL
      | Some OFPAT_DEC_NW_TTL -> DecNWTTL
      | Some OFPAT_SET_FIELD -> SetField
      | Some OFPAT_PUSH_PBB -> PushPBB
      | Some OFPAT_POP_PBB -> PopPBB
      | Some OFPAT_EXPERIMENTER -> Experimenter
      | None -> failwith "None type"

  let marshal (buf : Cstruct.t) (act : action) : int =
    let size = sizeof act in
    match act with
      | Output port ->
        set_ofp_action_output_typ buf 0; (* OFPAT_OUTPUT *)
        set_ofp_action_output_len buf size;
        set_ofp_action_output_port buf (PseudoPort.marshal port);
        set_ofp_action_output_max_len buf
          (match port with
            | Controller max_len -> max_len
            | _ -> 0);
        set_ofp_action_output_pad0 buf 0;
        set_ofp_action_output_pad1 buf 0;
        set_ofp_action_output_pad2 buf 0;
        set_ofp_action_output_pad3 buf 0;
        set_ofp_action_output_pad4 buf 0;
        set_ofp_action_output_pad5 buf 0;
        size
      | PushVlan ->
	set_ofp_action_push_typ buf 17; (* PUSH_VLAN *)
	set_ofp_action_push_len buf size;
	set_ofp_action_push_ethertype buf 0x8100;
	size
      | PopVlan ->
	set_ofp_action_header_typ buf 18; (* POP_VLAN *)
	set_ofp_action_header_len buf size;
        set_ofp_action_header_pad buf 0;
        set_ofp_action_header_pad1 buf 0;
        set_ofp_action_header_pad2 buf 0;
        set_ofp_action_header_pad3 buf 0;
	size
      | PushMpls ->
	set_ofp_action_push_typ buf 19; (* PUSH_MPLS *)
	set_ofp_action_push_len buf size;
	set_ofp_action_push_ethertype buf 0x8847;
	size
      | PopMpls ->
	set_ofp_action_pop_mpls_typ buf 20; (* POP_MPLS *)
	set_ofp_action_pop_mpls_len buf size;
	set_ofp_action_pop_mpls_ethertype buf 0x800;
	size
      | Group gid ->
        set_ofp_action_group_typ buf 22; (* OFPAT_GROUP *)
        set_ofp_action_group_len buf size;
        set_ofp_action_group_group_id buf gid;
        size
      | SetField oxm ->
        set_ofp_action_set_field_typ buf 25; (* OFPAT_SET_FIELD *)
        set_ofp_action_set_field_len buf size;
        let buf = Cstruct.shift buf sizeof_ofp_action_set_field in
        let oxm_size = Oxm.marshal buf oxm in
        let pad = size - (sizeof_ofp_action_set_field + oxm_size) in
        (* printf "pad = %d\n" pad; *)
        if pad > 0 then
          let buf = Cstruct.shift buf oxm_size in
          let _ = pad_with_zeros buf pad in
          size
        else size
      | CopyTtlOut ->
        set_ofp_action_header_typ buf 11; (* OFPAT_COPY_TTL_OUT *)
        set_ofp_action_header_len buf size;
        set_ofp_action_header_pad buf 0;
        set_ofp_action_header_pad1 buf 0;
        set_ofp_action_header_pad2 buf 0;
        set_ofp_action_header_pad3 buf 0;
        size
      | CopyTtlIn ->
        set_ofp_action_header_typ buf 12; (* OFPAT_COPY_TTL_IN *)
        set_ofp_action_header_len buf size;
        set_ofp_action_header_pad buf 0;
        set_ofp_action_header_pad1 buf 0;
        set_ofp_action_header_pad2 buf 0;
        set_ofp_action_header_pad3 buf 0;
        size
      | SetNwTtl newTtl ->
        set_ofp_action_nw_ttl_typ buf 23; (* OFPAT_SET_NW_TTL *)
        set_ofp_action_nw_ttl_len buf size;
        set_ofp_action_nw_ttl_nw_ttl buf newTtl;
        set_ofp_action_nw_ttl_pad buf 0;
        set_ofp_action_nw_ttl_pad1 buf 0;
        set_ofp_action_nw_ttl_pad2 buf 0;
        size
      | DecNwTtl ->
        set_ofp_action_header_typ buf 24; (* OFPAT_DEC_NW_TTL *)
        set_ofp_action_header_len buf size;
        set_ofp_action_header_pad buf 0;
        set_ofp_action_header_pad1 buf 0;
        set_ofp_action_header_pad2 buf 0;
        set_ofp_action_header_pad3 buf 0;
        size
      | PushPbb ->
        set_ofp_action_push_typ buf 26; (* OFPAT_PUSH_PBB *)
        set_ofp_action_push_len buf size;
        set_ofp_action_push_ethertype buf 0x88a8; (* Not sure, maybe need to redefine*)
        size
      | PopPbb ->
        set_ofp_action_header_typ buf 27; (* OFPAT_POP_PBB *)
        set_ofp_action_header_len buf size;
        set_ofp_action_header_pad buf 0;
        set_ofp_action_header_pad1 buf 0;
        set_ofp_action_header_pad2 buf 0;
        set_ofp_action_header_pad3 buf 0;
        size
      | SetMplsTtl newTtl ->
        set_ofp_action_mpls_ttl_typ buf 15; (* OFPAT_SET_MPLS_TTL *)
        set_ofp_action_mpls_ttl_len buf size;
        set_ofp_action_mpls_ttl_mpls_ttl buf newTtl;
        size
      | DecMplsTtl ->
        set_ofp_action_header_typ buf 16; (* OFPAT_DEC_MPLS_TTL *)
        set_ofp_action_header_len buf size;
        set_ofp_action_header_pad buf 0;
        set_ofp_action_header_pad1 buf 0;
        set_ofp_action_header_pad2 buf 0;
        set_ofp_action_header_pad3 buf 0;
        size
      | SetQueue queueId ->
        set_ofp_action_set_queue_typ buf 21; (* OFPAT_SET_QUEUE *)
        set_ofp_action_set_queue_len buf size;
        set_ofp_action_set_queue_queue_id buf queueId;
        size
      | Experimenter exp ->
        set_ofp_action_experimenter_typ buf 0xffff; (* OFPAT_EXPERIMENTER *)
        set_ofp_action_experimenter_len buf size;
        set_ofp_action_experimenter_experimenter buf exp;
        size

  let parse (bits : Cstruct.t) : action =
    match to_type (get_ofp_action_header_typ bits) with
     | Output -> Output (PseudoPort.make (get_ofp_action_output_port bits) 
     (get_ofp_action_output_max_len bits))
     | Group -> Group (get_ofp_action_group_group_id bits)
     | PushVLAN -> PushVlan
     | PopVLAN -> PopVlan
     | PushMPLS -> PushMpls
     | PopMPLS -> PopMpls
     | SetField -> let field,_ = Oxm.parse (
     Cstruct.shift bits 4) in (*TEST BECAUSE OF WRONG OFFSET??*)
     SetField (field)
     | CopyTTLOut -> CopyTtlOut
     | CopyTTLIn -> CopyTtlIn
     | SetMPLSTTL -> SetMplsTtl (get_ofp_action_mpls_ttl_mpls_ttl bits)
     | DecMPLSTTL -> DecMplsTtl
     | SetQueue -> SetQueue (get_ofp_action_set_queue_queue_id bits)
     | SetNWTTL -> SetNwTtl (get_ofp_action_nw_ttl_nw_ttl bits)
     | DecNWTTL -> DecNwTtl
     | PushPBB -> PushPbb
     | PopPBB  -> PopPbb
     | Experimenter -> Experimenter (get_ofp_action_experimenter_experimenter bits)

  let rec parse_fields (bits : Cstruct.t) : sequence * Cstruct.t =
    if Cstruct.len bits < sizeof_ofp_action_header then ([], bits)
    else let field = parse bits in
    let bits2 = Cstruct.shift bits (sizeof field) in
    let fields, bits3 = parse_fields bits2 in
    (List.append [field] fields, bits3)

  let parse_sequence (bits : Cstruct.t) : sequence =
    let fields, _ = parse_fields bits in
    fields

  let to_string seq =
      match seq with
        | Output o -> Format.sprintf "PseudoPort: %s" (PseudoPort.to_string o)
        | Group g -> Format.sprintf "Group ID: %lu" g
        | PopVlan -> "Pop Vlan"
        | PushVlan -> "Push Vlan"
        | PopMpls -> "Pop Mpls"
        | PushMpls -> "Push Mpls"
        | SetField oxm -> Format.sprintf "oxm: %s" (Oxm.to_string oxm)
        | CopyTtlOut -> "Copy TTL out"
        | CopyTtlIn -> "Copy TTL In"
        | SetNwTtl t -> Format.sprintf "Set NW TTL %u" t
        | DecNwTtl -> "Dec NW TTL"
        | PushPbb -> "Push PBB"
        | PopPbb -> "POP PBB"
        | SetMplsTtl t -> Format.sprintf "Set MPLS TTL: %u" t
        | DecMplsTtl -> "Dec MPLS TTL"
        | SetQueue q -> Format.sprintf "Set Queue: %lu" q
        | Experimenter e -> Format.sprintf "Experimenter: %lu" e
end

cstruct ofp_instruction {
    uint16_t typ;                 (* Instruction type *)
    uint16_t len                  (* Length of this struct in bytes. *)
} as big_endian

module Instruction = struct

  cenum ofp_instruction_type {
      OFPIT_GOTO_TABLE        = 1;
      OFPIT_WRITE_METADATA    = 2;
      OFPIT_WRITE_ACTIONS     = 3;
      OFPIT_APPLY_ACTIONS     = 4;
      OFPIT_CLEAR_ACTIONS     = 5;
      OFPIT_METER             = 6;
      OFPIT_EXPERIMENTER      = 0xFFFF;
  } as uint16_t

  (* Instruction structure for OFPIT_GOTO_TABLE *)
  cstruct ofp_instruction_goto_table {
      uint16_t typ;                 (* OFPIT_GOTO_TABLE *)
      uint16_t len;                 (* Length of this struct in bytes. *)
      uint8_t table_id;             (* Set next table in the lookup pipeline *)
      uint8_t pad0;                 (* Pad to 64 bits. *)
      uint8_t pad1;
      uint8_t pad2
  } as big_endian

  (* Instruction structure for OFPIT_WRITE_METADATA *)
  cstruct ofp_instruction_write_metadata {
      uint16_t typ;                 (* OFPIT_WRITE_METADATA *)
      uint16_t len;                 (* Length of this struct in bytes. *)
      uint8_t pad0;                 (* Align to 64-bits *)
      uint8_t pad1;
      uint8_t pad2;
      uint8_t pad3;
      uint64_t metadata;            (* Metadata value to write *)
      uint64_t metadata_mask        (* Metadata write bitmask *)
  } as big_endian

  (* Instruction structure for OFPIT_WRITE/APPLY/CLEAR_ACTIONS *)
  cstruct ofp_instruction_actions {
      uint16_t typ;               (* One of OFPIT_*_ACTIONS *)
      uint16_t len;               (* Length of this struct in bytes. *)
      uint8_t pad0;               (* Align to 64-bits *)
      uint8_t pad1;
      uint8_t pad2;
      uint8_t pad3
  } as big_endian

  (* Instruction structure for OFPIT_METER *)
  cstruct ofp_instruction_meter {
      uint16_t typ;                 (* OFPIT_METER *)
      uint16_t len;                 (* Length is 8. *)
      uint32_t meter_id             (* Meter instance. *)
  } as big_endian

  (* Instruction structure for experimental instructions *)
  cstruct ofp_instruction_experimenter {
      uint16_t typ;               (* OFPIT_EXPERIMENTER *)
      uint16_t len;               (* Length of this struct in bytes *)
      uint32_t experimenter       (* Experimenter ID which takes the same form
                                     as in struct ofp_experimenter_header. *)
      (* Experimenter-defined arbitrary additional data. *)
  } as big_endian

  type t = instruction

  let to_string ins =
    match ins with
      | GotoTable t -> Format.sprintf "Go to Table = %u" t
      | ApplyActions actions -> Format.sprintf "Apply Actions = [ %s ]"
                                (String.concat "; " (map Action.to_string actions))
      | WriteActions actions -> Format.sprintf "Write Actions = [ %s ]" 
                                (String.concat "; " (map Action.to_string actions))
      | WriteMetadata meta -> 
        (match meta.m_mask with
          | None -> Format.sprintf "WriteMeta = %LX" meta.m_value
          | Some m -> Format.sprintf "WriteMeta = %LX/%LX" meta.m_value m)
      | Clear -> "Clear"
      | Meter m -> Format.sprintf "Meter = %lu" m
      | Experimenter e -> Format.sprintf "Experimenter = %lu" e

  let sizeof (ins : instruction) : int =
    match ins with
      | GotoTable _ ->
        sizeof_ofp_instruction_goto_table
      | ApplyActions actions ->
        sizeof_ofp_instruction_actions + sum (map Action.sizeof actions)
      | WriteActions actions ->
        sizeof_ofp_instruction_actions + sum (map Action.sizeof actions)
      | WriteMetadata _ -> sizeof_ofp_instruction_write_metadata
      | Clear -> sizeof_ofp_instruction_actions
      | Meter _ -> sizeof_ofp_instruction_meter
      | Experimenter _ -> sizeof_ofp_instruction_experimenter

  let marshal (buf : Cstruct.t) (ins : instruction) : int =
    let size = sizeof ins in
      match ins with
        | GotoTable table_id ->
          set_ofp_instruction_goto_table_typ buf 1; (* OFPIT_GOTO_TABLE *)
          set_ofp_instruction_goto_table_len buf size;
          set_ofp_instruction_goto_table_table_id buf table_id;
          set_ofp_instruction_goto_table_pad0 buf 0;
          set_ofp_instruction_goto_table_pad1 buf 0;
          set_ofp_instruction_goto_table_pad2 buf 0;
          size
        | WriteActions actions ->
          set_ofp_instruction_actions_typ buf 3; (* OFPIT_WRITE_ACTIONS *)
          set_ofp_instruction_actions_len buf size;
          set_ofp_instruction_actions_pad0 buf 0;
          set_ofp_instruction_actions_pad1 buf 0;
          set_ofp_instruction_actions_pad2 buf 0;
          set_ofp_instruction_actions_pad3 buf 0;
          sizeof_ofp_instruction_actions + (
          marshal_fields 
          (Cstruct.shift buf sizeof_ofp_instruction_actions)
          actions
          Action.marshal)
        | ApplyActions actions ->
          set_ofp_instruction_actions_typ buf 4; (* OFPIT_APPLY_ACTIONS *)
          set_ofp_instruction_actions_len buf size;
          set_ofp_instruction_actions_pad0 buf 0;
          set_ofp_instruction_actions_pad1 buf 0;
          set_ofp_instruction_actions_pad2 buf 0;
          set_ofp_instruction_actions_pad3 buf 0;
          sizeof_ofp_instruction_actions + (marshal_fields (Cstruct.shift buf sizeof_ofp_instruction_actions) actions Action.marshal)
        | WriteMetadata metadata ->
          set_ofp_instruction_write_metadata_typ buf 2; (* OFPIT_WRITE_METADATA *)
          set_ofp_instruction_write_metadata_len buf size;
          set_ofp_instruction_write_metadata_pad0 buf 0;
          set_ofp_instruction_write_metadata_pad1 buf 0;
          set_ofp_instruction_write_metadata_pad2 buf 0;
          set_ofp_instruction_write_metadata_pad3 buf 0;
          set_ofp_instruction_write_metadata_metadata buf metadata.m_value;
          set_ofp_instruction_write_metadata_metadata_mask buf (
            match metadata.m_mask with
              | None -> 0L
              | Some mask -> mask);
          size
        | Clear -> 
          set_ofp_instruction_actions_typ buf 5; (* OFPIT_CLEAR_ACTIONS *)
          set_ofp_instruction_actions_len buf size;
          set_ofp_instruction_actions_pad0 buf 0;
          set_ofp_instruction_actions_pad1 buf 0;
          set_ofp_instruction_actions_pad2 buf 0;
          set_ofp_instruction_actions_pad3 buf 0;
          size
        | Meter meterId->
          set_ofp_instruction_meter_typ buf 6; (* OFPIT_METER *)
          set_ofp_instruction_meter_len buf size;
          set_ofp_instruction_meter_meter_id buf meterId;
          size
        | Experimenter experimenterId->
          set_ofp_instruction_experimenter_typ buf 0xffff; (* OFPIT_EXPERIMENTER *)
          set_ofp_instruction_experimenter_len buf size;
          set_ofp_instruction_experimenter_experimenter buf experimenterId;
          size


  let parse (bits : Cstruct.t) : instruction =
    let typ = get_ofp_instruction_typ bits in
    let len = get_ofp_instruction_len bits in
      match (int_to_ofp_instruction_type typ) with
        | Some OFPIT_GOTO_TABLE -> GotoTable (
        get_ofp_instruction_goto_table_table_id bits)
        | Some OFPIT_WRITE_METADATA -> 
            let value = get_ofp_instruction_write_metadata_metadata bits in 
            let mask = get_ofp_instruction_write_metadata_metadata_mask bits in
            if mask <> 0L then
              WriteMetadata ({m_value = value; m_mask = Some mask})
            else
              WriteMetadata ({m_value = value; m_mask = None})
        | Some OFPIT_WRITE_ACTIONS -> WriteActions (
        Action.parse_sequence (Cstruct.sub bits sizeof_ofp_instruction_actions (len-sizeof_ofp_instruction_actions)))
        | Some OFPIT_APPLY_ACTIONS -> ApplyActions (
        Action.parse_sequence (Cstruct.sub bits sizeof_ofp_instruction_actions (len-sizeof_ofp_instruction_actions))) 
        | Some OFPIT_CLEAR_ACTIONS -> Clear
        | Some OFPIT_METER -> Meter (get_ofp_instruction_meter_meter_id bits)
        | Some OFPIT_EXPERIMENTER -> Experimenter (
        get_ofp_instruction_experimenter_experimenter bits)
        | _ -> raise (Unparsable (sprintf "Unkown instruction message"))
        
end

module Instructions = struct

  type t = instruction list

  let sizeof (inss : instruction list) : int =
    sum (map Instruction.sizeof inss)

  let marshal (buf : Cstruct.t) (inss : instruction list) : int =
    if sizeof inss <> 0 then
      marshal_fields buf inss Instruction.marshal
    else 0

  let rec parse_field (bits : Cstruct.t) : instruction list*Cstruct.t =
    if Cstruct.len bits < sizeof_ofp_instruction then [],bits
    else let field = Instruction.parse bits in
    let bits2 = Cstruct.shift bits (Instruction.sizeof field) in
    let fields, bits3 = parse_field bits2 in
    (List.append [field] fields, bits3)

  let to_string ins =
    "[ " ^ (String.concat "; " (map Instruction.to_string ins)) ^ " ]"
    

  let parse (bits : Cstruct.t) : instruction list =
    let field,_ = parse_field bits in
    field

end

module Experimenter = struct

  cstruct ofp_experimenter_structure {
    uint32_t experimenter;
    uint32_t exp_typ
  } as big_endian

  type t = experimenter

  let sizeof (_ : experimenter) : int = 
    sizeof_ofp_experimenter_structure

  let to_string (exp : experimenter) : string =
    Format.sprintf "{ experimenter = %lu; exp_typ = %lu }" 
    exp.experimenter
    exp.exp_typ

  let marshal (buf : Cstruct.t) (exp : t) : int =
    set_ofp_experimenter_structure_experimenter buf exp.experimenter;
    set_ofp_experimenter_structure_exp_typ buf exp.exp_typ;
    sizeof_ofp_experimenter_structure

  let parse (bits : Cstruct.t) : t = 
    { experimenter = get_ofp_experimenter_structure_experimenter bits
    ; exp_typ = get_ofp_experimenter_structure_exp_typ bits }

end

(* Controller to switch message *)

module SwitchFeatures = struct

  module Capabilities = struct

    type t = switchCapabilities

    let to_int32 (capa : t) : int32 = 
      Int32.logor (if capa.flow_stats then (Int32.shift_left 1l 0) else 0l)
       (Int32.logor (if capa.table_stats then (Int32.shift_left 1l 1) else 0l)
        (Int32.logor (if capa.port_stats then (Int32.shift_left 1l 2) else 0l)
         (Int32.logor (if capa.group_stats then (Int32.shift_left 1l 3) else 0l)
          (Int32.logor (if capa.ip_reasm then (Int32.shift_left 1l 5) else 0l)
           (Int32.logor (if capa.queue_stats then (Int32.shift_left 1l 6) else 0l)
             (if capa.port_blocked then (Int32.shift_left 1l 8) else 0l))))))

    let to_string (cap : t) : string =
        Format.sprintf "{ port_blocked = %B; queue_stats = %B; ip_reasm = %B; group_stats = %B; \
                          port_stats = %B; table_stats = %B; flow_stats = %B }"
        cap.port_blocked
        cap.queue_stats
        cap.ip_reasm
        cap.group_stats
        cap.port_stats
        cap.table_stats
        cap.flow_stats

    let parse (bits : int32) : t =
      { port_blocked = Bits.test_bit 8 bits;
        queue_stats = Bits.test_bit 6 bits;
        ip_reasm = Bits.test_bit 5 bits;
        group_stats = Bits.test_bit 3 bits;
        port_stats = Bits.test_bit 2 bits;
        table_stats = Bits.test_bit 1 bits;
        flow_stats = Bits.test_bit 0 bits;
      }

  end

  cstruct ofp_switch_features {
    uint64_t datapath_id;
    uint32_t n_buffers;
    uint8_t n_tables;
    uint8_t auxiliary_id;
    uint8_t pad0;
    uint8_t pad1;
    uint32_t capabilities; 
    uint32_t reserved
  } as big_endian 

  type t = { datapath_id : int64; num_buffers : int32;
             num_tables : int8; aux_id : int8;
             supported_capabilities : switchCapabilities }

  let sizeof (sw : t) : int =
      sizeof_ofp_switch_features

  let to_string (sw : t) : string =
      Format.sprintf "{ datapath_id = %Lu; num_buffers = %lu; num_Tables = %u; aux_id = %u; capabilities = %s }"
      sw.datapath_id
      sw.num_buffers
      sw.num_tables
      sw.aux_id
      (Capabilities.to_string sw.supported_capabilities)

  let marshal (buf : Cstruct.t) (features : t) : int =
    set_ofp_switch_features_datapath_id buf features.datapath_id;
    set_ofp_switch_features_n_buffers buf features.num_buffers;
    set_ofp_switch_features_n_tables buf features.num_tables;
    set_ofp_switch_features_auxiliary_id buf features.aux_id;
    set_ofp_switch_features_pad0 buf 0;
    set_ofp_switch_features_pad1 buf 0;
    set_ofp_switch_features_pad2 buf 0;
    set_ofp_switch_features_capabilities buf (Capabilities.to_int32 features.supported_capabilities); 
    sizeof_ofp_switch_features

  let parse (bits : Cstruct.t) : t =
    let datapath_id = get_ofp_switch_features_datapath_id bits in 
    let num_buffers = get_ofp_switch_features_n_buffers bits in
    let num_tables = get_ofp_switch_features_n_tables bits in
    let aux_id = get_ofp_switch_features_auxiliary_id bits in
    let supported_capabilities = Capabilities.parse
      (get_ofp_switch_features_capabilities bits) in
    { datapath_id; 
      num_buffers; 
      num_tables;
      aux_id; 
      supported_capabilities }

end


module Message = struct

  type t =
    | Hello
    | EchoRequest of bytes
    | EchoReply of bytes
    | Experimenter of experimenter
    | FeaturesRequest
    | FeaturesReply of SwitchFeatures.t

  let string_of_msg_code (msg : msg_code) : string = match msg with
    | HELLO -> "HELLO"
    | ECHO_REQ -> "ECHO_REQ"
    | ECHO_RESP -> "ECHO_RESP"
    | FEATURES_REQ -> "FEATURES_REQ"
    | FEATURES_RESP -> "FEATURES_RESP"
    | FLOW_MOD -> "FLOW_MOD"
    | GROUP_MOD -> "GROUP_MOD"
    | PACKET_IN -> "PACKET_IN"
    | PACKET_OUT -> "PACKET_OUT"
    | PORT_STATUS -> "PORT_STATUS"
    | MULTIPART_REQ -> "MULTIPART_REQ"
    | MULTIPART_RESP -> "MULTIPART_RESP"
    | BARRIER_REQ -> "BARRIER_REQ"
    | BARRIER_RESP -> "BARRIER_RESP"
    | ERROR -> "ERROR"
    | EXPERIMENTER -> "EXPERIMENTER"
    | GET_CONFIG_REQ -> "GET_CONFIG_REQ"
    | GET_CONFIG_RESP -> "GET_CONFIG_RESP"
    | SET_CONFIG -> "SET_CONFIG"
    | FLOW_REMOVED -> "FLOW_REMOVED"
    | PORT_MOD -> "PORT_MOD"
    | TABLE_MOD -> "TABLE_MOD"
    | ROLE_REQ -> "ROLE_REQ"
    | ROLE_RESP -> "ROLE_RESP"
    | GET_ASYNC_REQ -> "GET_ASYNC_REQ"
    | GET_ASYNC_REP -> "GET_ASYNC_REP"
    | SET_ASYNC -> "SET_ASYNC"
    | METER_MOD -> "METER_MOD"
    | ROLE_STATUS -> "ROLE_STATUS"
    | TABLE_STATUS -> "TABLE_STATUS"
    | REQUEST_FORWARD -> "REQUEST_FORWARD"
    | BUNDLE_CONTROL -> "BUNDLE_CONTROL"
    | BUNDLE_ADD_MESSAGE -> "BUNDLE_ADD_MESSAGE"


  module Header = OpenFlow_Header

  let msg_code_of_message (msg : t) : msg_code = match msg with
    | Hello -> HELLO
    | EchoRequest _ -> ECHO_REQ
    | EchoReply _ -> ECHO_RESP
    | Experimenter _ -> EXPERIMENTER
    | FeaturesRequest -> FEATURES_REQ
    | FeaturesReply _ -> FEATURES_RESP

  let sizeof (msg : t) : int = match msg with
    | Hello -> Header.size
    | EchoRequest bytes -> Header.size + (String.length (Cstruct.to_string bytes))
    | EchoReply bytes -> Header.size + (String.length (Cstruct.to_string bytes))
    | Experimenter exp -> Header.size + (Experimenter.sizeof exp)
    | FeaturesRequest -> Header.size
    | FeaturesReply f -> Header.size + (SwitchFeatures.sizeof f)

  let to_string (msg : t) : string = match msg with
    | Hello -> "Hello"
    | EchoRequest _ -> "EchoRequest"
    | EchoReply _ -> "EchoReply"
    | Experimenter _ -> "Experimenter"
    | FeaturesRequest -> "FeaturesRequest"
    | FeaturesReply _ -> "FeaturesReply"

  (* let marshal (buf : Cstruct.t) (msg : message) : int = *)
  (*   let buf2 = (Cstruct.shift buf Header.size) in *)
  (*   set_ofp_header_version buf 0x05; *)
  (*   set_ofp_header_typ buf (msg_code_to_int (msg_code_of_message msg)); *)
  (*   set_ofp_header_length buf (sizeof msg); *)

  let blit_message (msg : t) (out : Cstruct.t) =
    match msg with
      | Hello ->
        Header.size
      | EchoRequest bytes
      | EchoReply bytes ->
        Cstruct.blit_from_string (Cstruct.to_string bytes) 0 out 0 (String.length (Cstruct.to_string bytes));
        Header.size + String.length (Cstruct.to_string bytes)
      | Experimenter exp ->
        Header.size + Experimenter.marshal out exp
      | FeaturesRequest ->
        Header.size
      | FeaturesReply fr ->
        Header.size + SwitchFeatures.marshal out fr
      
  let header_of xid msg =
    let open Header in
    { version = 0x05; type_code = msg_code_to_int (msg_code_of_message msg);
      length = sizeof msg; xid = xid }

  let marshal_body (msg : t) (buf : Cstruct.t) =
    let _ = blit_message msg buf in
    ()
    
  let marshal (xid : xid) (msg : t) : string =
    let sizeof_buf = sizeof msg in
    let hdr = header_of xid msg in
    let buf = Cstruct.create sizeof_buf in
    Header.marshal buf hdr;
    let _ = blit_message msg (Cstruct.shift buf Header.size) in
    Cstruct.to_string buf

  let parse (hdr : Header.t) (body_buf : string) : (xid * t) =
    let body_bits = Cstruct.of_string body_buf in
    let typ = match int_to_msg_code hdr.Header.type_code with
      | Some code -> code
      | None -> raise (Unparsable "unknown message code") in
    let msg = match typ with
      | HELLO -> Hello
      | ECHO_REQ -> EchoRequest body_bits
      | ECHO_RESP -> EchoReply body_bits
      | EXPERIMENTER -> Experimenter (Experimenter.parse body_bits)
      | FEATURES_RESP -> FeaturesReply (SwitchFeatures.parse body_bits)
      | code -> raise (Unparsable (Printf.sprintf "unexpected message type %s" (string_of_msg_code typ))) in
    (hdr.Header.xid, msg)
end

