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

let ofpp_in_port = 0xfffffff8l
let ofpp_flood = 0xfffffffbl
let ofpp_all = 0xfffffffcl
let ofpp_controller = 0xfffffffdl
let ofpp_any = 0xffffffffl

let ofp_no_buffer = 0xffffffffl

(* Not in the spec, comes from C headers. :rolleyes: *)
let ofpg_all = 0xfffffffcl
let ofpg_any = 0xffffffffl
let ofp_eth_alen = 6          (* Bytes in an Ethernet address. *)

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

      type t = ethFeatures

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

      type t = opticalFeatures

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
        Format.sprintf "{ rx_tune : %B; tx_tune : %B; tx_pwr : %B; use_freq : %B }"
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
      else Some (get_ofp_port_desc_prop_header_len buf)

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

module PseudoPort = OpenFlow0x04.PseudoPort


module Action = OpenFlow0x04.Action

module Instruction = OpenFlow0x04.Instruction

module Instructions = OpenFlow0x04.Instructions

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

module Capabilities = OpenFlow0x04.Capabilities

module SwitchFeatures = struct

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

  type t = switchFeatures

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
module SwitchConfig = OpenFlow0x04.SwitchConfig

module TableMod = struct

  module Properties = struct

  cstruct ofp_table_mod_prop_header {
    uint16_t typ;
    uint16_t len
  } as  big_endian

  cenum ofp_table_mod_prop_type {
    OFPTMPT_EVICTION = 0x2;
    OFPTMPT_VACANCY = 0x3;
    OFPTMPT_EXPERIMENTER   = 0xffff
  } as uint16_t

    module Eviction = struct 

      cstruct ofp_table_mod_prop_eviction {
        uint16_t typ;
        uint16_t len;
        uint32_t flags
      } as  big_endian

      module Flags = struct

        type t = tableEviction

        let marshal (t : t) : int32 =
         Int32.logor (if t.other then (Int32.shift_left 1l 0) else 0l)  
          (Int32.logor (if t.importance then (Int32.shift_left 1l 1) else 0l)
           (if t.lifetime then (Int32.shift_left 1l 2) else 0l))

        let parse (bits : int32) : t =
          { other = Bits.test_bit 0 bits
          ; importance = Bits.test_bit 1 bits
          ; lifetime = Bits.test_bit 2 bits }

      end

      type t = tableEviction

      let sizeof (_ : t) : int =
        sizeof_ofp_table_mod_prop_eviction

      let to_string (t : t) : string =
        Format.sprintf "{ other = %B; importance = %B; lifetime = %B }"
        t.other
        t.importance
        t.lifetime

      let marshal (buf : Cstruct.t) (t : t) : int = 
        set_ofp_table_mod_prop_eviction_typ buf (ofp_table_mod_prop_type_to_int OFPTMPT_EVICTION);
        set_ofp_table_mod_prop_eviction_len buf (sizeof t);
        set_ofp_table_mod_prop_eviction_flags buf (Flags.marshal t);
        sizeof_ofp_table_mod_prop_eviction

      let parse (bits : Cstruct.t) : t =
        Flags.parse (get_ofp_table_mod_prop_eviction_flags bits)

    end

    module Vacancy = struct 

      cstruct ofp_table_mod_prop_vacancy {
        uint16_t typ;
        uint16_t len;
        uint8_t vacancy_down;
        uint8_t vacancy_up;
        uint8_t vacancy;
        uint8_t pad
      } as  big_endian  

      type t = tableVacancy

      let sizeof (_ : t) : int =
        sizeof_ofp_table_mod_prop_vacancy

      let to_string (t : t) : string = 
        Format.sprintf "{ vacancy_down = %u; vacancy_up = %u; vacancy = %u }"
        t.vacancy_down
        t.vacancy_up
        t.vacancy

      let marshal (buf : Cstruct.t) (t : t) : int = 
        set_ofp_table_mod_prop_vacancy_typ buf (ofp_table_mod_prop_type_to_int OFPTMPT_VACANCY);
        set_ofp_table_mod_prop_vacancy_len buf (sizeof t);
        set_ofp_table_mod_prop_vacancy_vacancy_down buf t.vacancy_down;
        set_ofp_table_mod_prop_vacancy_vacancy_up buf t.vacancy_up;
        set_ofp_table_mod_prop_vacancy_vacancy buf t.vacancy;
        sizeof_ofp_table_mod_prop_vacancy

      let parse (bits : Cstruct.t) : t =
        { vacancy_down = get_ofp_table_mod_prop_vacancy_vacancy_down bits
        ; vacancy_up = get_ofp_table_mod_prop_vacancy_vacancy_up bits
        ; vacancy = get_ofp_table_mod_prop_vacancy_vacancy bits}

    end

    module Experimenter = struct 

      cstruct ofp_table_mod_prop_experimenter {
        uint16_t typ;
        uint16_t len;
        uint32_t experimenter;
        uint32_t exp_typ
      } as  big_endian  

      type t = experimenter

      let sizeof (_ : t) : int =
        sizeof_ofp_table_mod_prop_experimenter

      let to_string (t : t) : string = 
        Format.sprintf "{ experimenter = %lu; exp_typ = %lu}"
        t.experimenter
        t.exp_typ

      let marshal (buf : Cstruct.t) (t : t) : int = 
        set_ofp_table_mod_prop_experimenter_typ buf (ofp_table_mod_prop_type_to_int OFPTMPT_EXPERIMENTER);
        set_ofp_table_mod_prop_experimenter_len buf (sizeof t);
        set_ofp_table_mod_prop_experimenter_experimenter buf t.experimenter;
        set_ofp_table_mod_prop_experimenter_exp_typ buf t.exp_typ;
        sizeof_ofp_table_mod_prop_experimenter

      let parse (bits : Cstruct.t) : t =
        { experimenter = get_ofp_table_mod_prop_experimenter_experimenter bits
        ; exp_typ = get_ofp_table_mod_prop_experimenter_exp_typ bits}
    end

    type t = tableProperties

    let sizeof (t : t) : int = 
      match t with
        | Eviction e -> Eviction.sizeof e
        | Vacancy v -> Vacancy.sizeof v
        | Experimenter e -> Experimenter.sizeof e

    let to_string (t : t) : string = 
      match t with
        | Eviction e -> Format.sprintf "Eviction = %s " (Eviction.to_string e)
        | Vacancy e -> Format.sprintf "Vacancy = %s " (Vacancy.to_string e)
        | Experimenter e -> Format.sprintf "Experimenter = %s " (Experimenter.to_string e)

    let marshal (buf : Cstruct.t) (t : t) : int =
      match t with 
        | Eviction e -> Eviction.marshal buf e
        | Vacancy v -> Vacancy.marshal buf v
        | Experimenter e -> Experimenter.marshal buf e

    let parse (bits : Cstruct.t) : t = 
      match int_to_ofp_table_mod_prop_type (get_ofp_table_mod_prop_header_typ bits) with
        | Some OFPTMPT_EVICTION -> Eviction (Eviction.parse bits)
        | Some OFPTMPT_VACANCY -> Vacancy (Vacancy.parse bits)
        | Some OFPTMPT_EXPERIMENTER -> Experimenter (Experimenter.parse bits)
        | None -> raise (Unparsable (sprintf "Malformed table mod prop type"))

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_table_mod_prop_header then None
      else Some (get_ofp_table_mod_prop_header_len buf)
  end

  module TableConfig = struct

    type t = tableConfig

    let marshal (t : t) : int32 =
     Int32.logor (if t.eviction then (Int32.shift_left 1l 2) else 0l)  
      (if t.vacancyEvent then (Int32.shift_left 1l 3) else 0l)

    (* don't care about deprecated bits (0 and 1) *)
    let parse (bits : int32) : t =
      { eviction = Bits.test_bit 2 bits
      ; vacancyEvent = Bits.test_bit 3 bits }

    let to_string tc =
      Format.sprintf "{ eviction = %B; vacancyEvent = %B }"
      tc.eviction
      tc.vacancyEvent

  end

  cstruct ofp_table_mod {
    uint8_t table_id;
    uint8_t pad[3];
    uint32_t config
  } as big_endian

  type t = tableMod

  let sizeof (tab : tableMod) : int =
    sizeof_ofp_table_mod + sum (map Properties.sizeof tab.properties)

  let to_string (tab : tableMod) : string =
    Format.sprintf "{ tabled_id = %u; config = %s; properties = %s }"
    tab.table_id
    (TableConfig.to_string tab.config)
    ("[ " ^ (String.concat "; " (map Properties.to_string tab.properties))^ " ]")

  let marshal (buf : Cstruct.t) (tab : tableMod) : int =
    set_ofp_table_mod_table_id buf tab.table_id;
    set_ofp_table_mod_config buf (TableConfig.marshal tab.config);
    sizeof_ofp_table_mod + (marshal_fields (Cstruct.shift buf sizeof_ofp_table_mod) tab.properties Properties.marshal)

  let parse (bits : Cstruct.t) : tableMod =
    let table_id = get_ofp_table_mod_table_id bits in
    let config = TableConfig.parse (get_ofp_table_mod_config bits) in
    let properties = parse_fields (Cstruct.shift bits sizeof_ofp_table_mod) Properties.parse Properties.length_func in
    { table_id; config; properties }

end

module FlowMod = struct
  cstruct ofp_flow_mod {
    uint64_t cookie;             (* Opaque controller-issued identifier. *)
    uint64_t cookie_mask;        (* Mask used to restrict the cookie bits
                                    that must match when the command is
                                    OFPFC_MODIFY* or OFPFC_DELETE*. A value
                                    of 0 indicates no restriction. *)

    (* Flow actions. *)
    uint8_t table_id;             (* ID of the table to put the flow in.
                                     For OFPFC_DELETE_* commands, OFPTT_ALL
                                     can also be used to delete matching
                                     flows from all tables. *)
    uint8_t command;              (* One of OFPFC_*. *)
    uint16_t idle_timeout;        (* Idle time before discarding (seconds). *)
    uint16_t hard_timeout;        (* Max time before discarding (seconds). *)
    uint16_t priority;            (* Priority level of flow entry. *)
    uint32_t buffer_id;           (* Buffered packet to apply to, or
                                     OFP_NO_BUFFER.
                                     Not meaningful for OFPFC_DELETE*. *)
    uint32_t out_port;            (* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output port.  A value of OFPP_ANY
                                     indicates no restriction. *)
    uint32_t out_group;           (* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output group.  A value of OFPG_ANY
                                     indicates no restriction. *)
    uint16_t flags;               (* One of OFPFF_*. *)
    uint16_t importance
  } as big_endian

  module FlowModCommand = struct
    cenum ofp_flow_mod_command {
      OFPFC_ADD            = 0; (* New flow. *)
      OFPFC_MODIFY         = 1; (* Modify all matching flows. *)
      OFPFC_MODIFY_STRICT  = 2; (* Modify entry strictly matching wildcards and
                                  priority. *)
      OFPFC_DELETE         = 3; (* Delete all matching flows. *)
      OFPFC_DELETE_STRICT  = 4  (* Delete entry strictly matching wildcards and
                                  priority. *)
  } as uint8_t
  
    type t = flowModCommand

    let n = ref 0L
    
    let sizeof _ = 1

    let marshal (t : t) : int = match t with
      | AddFlow -> n := Int64.succ !n; ofp_flow_mod_command_to_int OFPFC_ADD
      | ModFlow -> ofp_flow_mod_command_to_int OFPFC_MODIFY
      | ModStrictFlow -> ofp_flow_mod_command_to_int OFPFC_MODIFY_STRICT
      | DeleteFlow -> ofp_flow_mod_command_to_int OFPFC_DELETE
      | DeleteStrictFlow -> ofp_flow_mod_command_to_int OFPFC_DELETE_STRICT

    let parse bits : flowModCommand = 
      match (int_to_ofp_flow_mod_command bits) with
        | Some OFPFC_ADD -> AddFlow
        | Some OFPFC_MODIFY -> ModFlow
        | Some OFPFC_MODIFY_STRICT -> ModStrictFlow
        | Some OFPFC_DELETE -> DeleteFlow
        | Some OFPFC_DELETE_STRICT -> DeleteStrictFlow
        | None -> raise (Unparsable (sprintf "malformed command"))

    let to_string t = 
     match t with
      | AddFlow -> "Add"
      | ModFlow -> "Modify"
      | ModStrictFlow -> "ModifyStrict"
      | DeleteFlow -> "Delete"
      | DeleteStrictFlow -> "DeleteStrict"
  end

  type t = flowMod

  let sizeof (fm : flowMod) =
    sizeof_ofp_flow_mod + (OfpMatch.sizeof fm.mfOfp_match) + (Instructions.sizeof fm.mfInstructions)

  module Flags = struct
    
    let marshal (f : flowModFlags) =
      (if f.fmf_send_flow_rem then 1 lsl 0 else 0) lor
        (if f.fmf_check_overlap then 1 lsl 1 else 0) lor
          (if f.fmf_reset_counts then 1 lsl 2 else 0) lor
            (if f.fmf_no_pkt_counts then 1 lsl 3 else 0) lor
              (if f.fmf_no_byt_counts then 1 lsl 4 else 0)

    let parse bits : flowModFlags =
      { fmf_send_flow_rem = test_bit16  0 bits
      ; fmf_check_overlap = test_bit16  1 bits
      ; fmf_reset_counts = test_bit16  2 bits
      ; fmf_no_pkt_counts = test_bit16  3 bits
      ; fmf_no_byt_counts = test_bit16  4 bits
      }

    let to_string f =
      Format.sprintf "{ send_flow_rem = %B; check_overlap = %B; reset_counts = %B; \
                     no_pkt_counts = %B; no_byt_counts = %B }"
                     f.fmf_send_flow_rem
                     f.fmf_check_overlap
                     f.fmf_reset_counts
                     f.fmf_no_pkt_counts
                     f.fmf_no_byt_counts

  end 

  let marshal (buf : Cstruct.t) (fm : flowMod) : int =
    set_ofp_flow_mod_cookie buf fm.mfCookie.m_value;
    set_ofp_flow_mod_cookie_mask buf (
      match fm.mfCookie.m_mask with
        | None -> 0L
        | Some mask -> mask);
    set_ofp_flow_mod_table_id buf fm.mfTable_id;
    set_ofp_flow_mod_command buf (FlowModCommand.marshal fm.mfCommand);
    set_ofp_flow_mod_idle_timeout buf
      (match fm.mfIdle_timeout with
        | Permanent -> 0
        | ExpiresAfter value -> value);
    set_ofp_flow_mod_hard_timeout buf
      (match fm.mfHard_timeout with
        | Permanent -> 0
        | ExpiresAfter value -> value);
    set_ofp_flow_mod_priority buf fm.mfPriority;
    set_ofp_flow_mod_buffer_id buf
      (match fm.mfBuffer_id with
        | None -> ofp_no_buffer
        | Some bid -> bid);
    set_ofp_flow_mod_out_port buf
      (match fm.mfOut_port with
        | None -> 0l
        | Some port -> PseudoPort.marshal port);
    set_ofp_flow_mod_out_group buf
      (match fm.mfOut_group with
        | None -> 0l
        | Some gid -> gid);
    set_ofp_flow_mod_flags buf (Flags.marshal fm.mfFlags);
    set_ofp_flow_mod_importance buf fm.mfImportance;
    let size = sizeof_ofp_flow_mod +
        OfpMatch.marshal 
         (Cstruct.sub buf sizeof_ofp_flow_mod (OfpMatch.sizeof fm.mfOfp_match))
         fm.mfOfp_match in
      size + Instructions.marshal (Cstruct.shift buf size) fm.mfInstructions

  let parse (bits : Cstruct.t) : flowMod =
    let mfMask = get_ofp_flow_mod_cookie_mask bits in
    let mfCookie =
      if mfMask <> 0L then
        {m_value = get_ofp_flow_mod_cookie bits;
        m_mask = (Some (get_ofp_flow_mod_cookie_mask bits))}
    else {m_value = get_ofp_flow_mod_cookie bits;
        m_mask = None}
      in
    let mfTable_id = get_ofp_flow_mod_table_id bits in
    let mfCommand = FlowModCommand.parse (get_ofp_flow_mod_command bits) in
    let mfIdle_timeout = match (get_ofp_flow_mod_idle_timeout bits) with
                         | 0 -> Permanent 
                         | n -> ExpiresAfter n in
    let mfHard_timeout = match (get_ofp_flow_mod_hard_timeout bits) with
                         | 0 -> Permanent 
                         | n -> ExpiresAfter n in
    let mfPriority = get_ofp_flow_mod_priority bits in
    let mfBuffer_id = match (get_ofp_flow_mod_buffer_id bits) with
        | 0xffffffffl -> None
        | n -> Some n in
    let mfOut_port = match (get_ofp_flow_mod_out_port bits) with
        | 0l -> None
        | _ -> Some (PseudoPort.make (get_ofp_flow_mod_out_port bits) 0) in
    let mfOut_group = match (get_ofp_flow_mod_out_group bits) with
        | 0l -> None
        | n -> Some n in
    let mfFlags = Flags.parse (get_ofp_flow_mod_flags bits) in
    let mfImportance = get_ofp_flow_mod_importance bits in
    let mfOfp_match,instructionsBits = OfpMatch.parse (Cstruct.shift bits sizeof_ofp_flow_mod) in
    let mfInstructions = Instructions.parse instructionsBits in
    { mfCookie; mfTable_id;
      mfCommand; mfIdle_timeout;
      mfHard_timeout; mfPriority;
      mfBuffer_id;
      mfOut_port;
      mfOut_group; mfFlags; mfImportance;
      mfOfp_match; mfInstructions}
  
  let to_string (flow : flowMod) =
    Format.sprintf "{ cookie = %s; table = %u; command = %s; idle_timeout = %s; \
                      hard_timeout = %s; priority = %u; bufferId = %s; out_port = %s; \
                      out_group = %s; flags = %s; importance = %u; match = %s; instructions = %s }"
    (match flow.mfCookie.m_mask with
        | None -> Int64.to_string flow.mfCookie.m_value
        | Some m -> Format.sprintf "%LX/%LX" flow.mfCookie.m_value m)
    flow.mfTable_id
    (FlowModCommand.to_string flow.mfCommand)
    (match flow.mfIdle_timeout with
        | Permanent -> "Permanent"
        | ExpiresAfter t-> string_of_int t)
    (match flow.mfHard_timeout with
        | Permanent -> "Permanent"
        | ExpiresAfter t-> string_of_int t)
    flow.mfPriority
    (match flow.mfBuffer_id with
        | None -> "None"
        | Some t -> Int32.to_string t)
    (match flow.mfOut_port with
        | None -> "None"
        | Some t -> PseudoPort.to_string t)
    (match flow.mfOut_group with
        | None -> "None"
        | Some t -> Int32.to_string t)
    (Flags.to_string flow.mfFlags)
    flow.mfImportance
    (OfpMatch.to_string flow.mfOfp_match)
    (Instructions.to_string flow.mfInstructions)
end

module Bucket = OpenFlow0x04.Bucket

module GroupMod = OpenFlow0x04.GroupMod

module PortMod = struct

  cstruct ofp_port_mod {
    uint32_t port_no;
    uint8_t pad[4];
    uint8_t hw_addr[6];
    uint8_t pad2[2];
    uint32_t config;
    uint32_t mask;
  } as big_endian

  module Properties = struct

    cenum ofp_port_mod_prop_type {
      OFPPMPT_ETHERNET = 0;
      OFPPMPT_OPTICAL = 1;
      OFPPMPT_EXPERIMENTER = 0xffff
    } as uint16_t

    module Ethernet = struct
      cstruct ofp_port_mod_prop_ethernet {
        uint16_t typ;
        uint16_t len;
        uint32_t advertise
      } as big_endian

      type t = portModPropEthernet

      let to_string = PortDesc.State.to_string

      let sizeof (t : portState) = 
        sizeof_ofp_port_mod_prop_ethernet

      let marshal (buf : Cstruct.t) (t : portState) : int =
        set_ofp_port_mod_prop_ethernet_typ buf (ofp_port_mod_prop_type_to_int OFPPMPT_ETHERNET);
        set_ofp_port_mod_prop_ethernet_len buf sizeof_ofp_port_mod_prop_ethernet;
        set_ofp_port_mod_prop_ethernet_advertise buf (PortDesc.State.marshal t);
        sizeof_ofp_port_mod_prop_ethernet

      let parse (bits : Cstruct.t) : t =
        PortDesc.State.parse (get_ofp_port_mod_prop_ethernet_advertise bits)

    end

    module Optical = struct
      cstruct ofp_port_mod_prop_optical {
        uint16_t typ;
        uint16_t len;
        uint32_t configure;
        uint32_t freq_lmda;
        int32_t fl_offset;
        uint32_t grid_span;
        uint32_t tx_pwr
      } as big_endian

      type t = portModPropOptical

      let sizeof (_ : t) =
        sizeof_ofp_port_mod_prop_optical

      let to_string (t : t) = 
        Format.sprintf "{ configure = %s; freq_lmda = %lu; fl_offset = %lu; 
                          grid_span = %lu; tx_pwr = %lu }"
        (PortDesc.Properties.OptFeatures.to_string t.configure)
        t.freq_lmda
        t.fl_offset
        t.grid_span
        t.tx_pwr

      let marshal (buf : Cstruct.t) (t : t) : int =
        set_ofp_port_mod_prop_optical_typ buf (ofp_port_mod_prop_type_to_int OFPPMPT_OPTICAL);
        set_ofp_port_mod_prop_optical_len buf sizeof_ofp_port_mod_prop_optical;
        set_ofp_port_mod_prop_optical_configure buf (PortDesc.Properties.OptFeatures.marshal t.configure);
        set_ofp_port_mod_prop_optical_freq_lmda buf t.freq_lmda;
        set_ofp_port_mod_prop_optical_fl_offset buf t.fl_offset;
        set_ofp_port_mod_prop_optical_grid_span buf t.grid_span;
        set_ofp_port_mod_prop_optical_tx_pwr buf t.tx_pwr;
        sizeof_ofp_port_mod_prop_optical

      let parse (bits : Cstruct.t) : t =
        { configure = PortDesc.Properties.OptFeatures.parse (get_ofp_port_mod_prop_optical_configure bits)
        ; freq_lmda = get_ofp_port_mod_prop_optical_freq_lmda bits
        ; fl_offset = get_ofp_port_mod_prop_optical_fl_offset bits
        ; grid_span = get_ofp_port_mod_prop_optical_grid_span bits
        ; tx_pwr = get_ofp_port_mod_prop_optical_tx_pwr bits }

    end

    module Experimenter = struct

      cstruct ofp_port_mod_prop_experimenter {
        uint16_t typ;
        uint16_t len;
        uint32_t experimenter;
        uint32_t exp_typ
      } as big_endian

      type t = experimenter

      let to_string (t : t) : string =
        Format.sprintf "{ experimenter : %lu; exp_typ : %lu }"
         t.experimenter
         t.exp_typ

      let sizeof ( _ : t ) =
        sizeof_ofp_port_mod_prop_experimenter

      let marshal (buf : Cstruct.t) (t : t) : int =
        set_ofp_port_mod_prop_experimenter_typ buf (ofp_port_mod_prop_type_to_int OFPPMPT_EXPERIMENTER);
        set_ofp_port_mod_prop_experimenter_len buf sizeof_ofp_port_mod_prop_experimenter;
        set_ofp_port_mod_prop_experimenter_experimenter buf t.experimenter;
        set_ofp_port_mod_prop_experimenter_exp_typ buf t.exp_typ;
        sizeof_ofp_port_mod_prop_experimenter

      let parse (bits : Cstruct.t) : t =
        { experimenter = get_ofp_port_mod_prop_experimenter_experimenter bits
        ; exp_typ = get_ofp_port_mod_prop_experimenter_exp_typ bits}

    end

    cstruct ofp_port_mod_prop_header {
      uint16_t typ;
      uint16_t len;
    } as big_endian

    type t = portModPropt

    let sizeof (t : t) : int =
      match t with 
        | PortModPropEthernet p -> Ethernet.sizeof p
        | PortModPropOptical p -> Optical.sizeof p
        | PortModPropExperiment p -> Experimenter.sizeof p

    let to_string (t : t) : string = 
      match t with 
        | PortModPropEthernet p -> Format.sprintf "Ethernet : %s" (Ethernet.to_string p)
        | PortModPropOptical p -> Format.sprintf "Optical : %s" (Optical.to_string p)
        | PortModPropExperiment p -> Format.sprintf "Experimenter : %s" (Experimenter.to_string p)

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_port_mod_prop_header then None
      else Some (get_ofp_port_mod_prop_header_len buf)

    let marshal (buf : Cstruct.t) (t : t) =
      match t with
        | PortModPropEthernet p -> Ethernet.marshal buf p
        | PortModPropOptical p -> Optical.marshal buf p
        | PortModPropExperiment p -> Experimenter.marshal buf p

    let parse (bits : Cstruct.t) : t =
      let typ = match int_to_ofp_port_mod_prop_type (get_ofp_port_mod_prop_header_typ bits) with
        | Some v -> v
        | None -> raise (Unparsable (sprintf "malformed prop typ")) in
      match typ with 
        | OFPPMPT_ETHERNET -> PortModPropEthernet (Ethernet.parse bits)
        | OFPPMPT_OPTICAL -> PortModPropOptical (Optical.parse bits)
        | OFPPMPT_EXPERIMENTER -> PortModPropExperiment (Experimenter.parse bits)


  end

  type t = portMod

  let sizeof pm : int =
    sizeof_ofp_port_mod + sum (map Properties.sizeof pm.mpProp)

  let to_string (pm : t) : string =
    Format.sprintf "{ port_no = %lu; hw_addr = %s; config = %s; mask = %s; properties = %s }"
    pm.mpPortNo
    (string_of_mac pm.mpHw_addr)
    (PortDesc.Config.to_string pm.mpConfig)
    (PortDesc.Config.to_string pm.mpMask)
    ("[ " ^ (String.concat "; " (map Properties.to_string pm.mpProp)) ^ " ]")
    
  let marshal (buf : Cstruct.t) (pm : t) : int =
    set_ofp_port_mod_port_no buf pm.mpPortNo;
    set_ofp_port_mod_hw_addr (bytes_of_mac pm.mpHw_addr) 0 buf;
    set_ofp_port_mod_config buf (PortDesc.Config.marshal pm.mpConfig);
    set_ofp_port_mod_mask buf (PortDesc.Config.marshal pm.mpMask);
    sizeof_ofp_port_mod + marshal_fields (Cstruct.shift buf sizeof_ofp_port_mod) pm.mpProp Properties.marshal

  let parse (bits : Cstruct.t) : t =
    let mpPortNo = get_ofp_port_mod_port_no bits in
    let mpHw_addr = mac_of_bytes (copy_ofp_port_mod_hw_addr bits) in
    let mpConfig = PortDesc.Config.parse (get_ofp_port_mod_config bits) in
    let mpMask = PortDesc.Config.parse (get_ofp_port_mod_mask bits) in
    let mpProp = parse_fields (Cstruct.shift bits sizeof_ofp_port_mod) Properties.parse Properties.length_func in
    { mpPortNo; mpHw_addr; mpConfig; mpMask; mpProp}

end

module MeterMod = OpenFlow0x04.MeterMod


module FlowRemoved = struct

  module Reason = struct

    cenum ofp_flow_removed_reason {
      OFPRR_IDLE_TIMEOUT = 0;
      OFPRR_HARD_TIMEOUT = 1;
      OFPRR_DELETE = 2;
      OFPRR_GROUP_DELETE = 3;
      OFPRR_METER_DELETE = 4;
      OFPRR_EVICTION = 5
    } as uint8_t

    type t = flowReason

    let to_string (t : flowReason) : string =
      match t with
        | FlowIdleTimeout -> "IDLE_TIMEOUT"
        | FlowHardTiemout -> "HARD_TIMEOUT"
        | FlowDelete -> "DELETE"
        | FlowGroupDelete -> "GROUP_DELETE"
        | FlowMeterDelete -> "METER_DELETE"
        | FlowEviction -> "EVICTION"

    let marshal (t : flowReason) : int8 =
      match t with
        | FlowIdleTimeout -> ofp_flow_removed_reason_to_int OFPRR_IDLE_TIMEOUT
        | FlowHardTiemout -> ofp_flow_removed_reason_to_int OFPRR_HARD_TIMEOUT
        | FlowDelete -> ofp_flow_removed_reason_to_int OFPRR_DELETE
        | FlowGroupDelete -> ofp_flow_removed_reason_to_int OFPRR_GROUP_DELETE
        | FlowMeterDelete -> ofp_flow_removed_reason_to_int OFPRR_METER_DELETE
        | FlowEviction -> ofp_flow_removed_reason_to_int OFPRR_EVICTION

    let parse bits : flowReason =
      match (int_to_ofp_flow_removed_reason bits) with
        | Some OFPRR_IDLE_TIMEOUT -> FlowIdleTimeout
        | Some OFPRR_HARD_TIMEOUT -> FlowHardTiemout
        | Some OFPRR_DELETE -> FlowDelete
        | Some OFPRR_GROUP_DELETE -> FlowGroupDelete
        | Some OFPRR_METER_DELETE -> FlowMeterDelete
        | Some OFPRR_EVICTION -> FlowEviction
        | None -> raise (Unparsable (sprintf "malformed reason"))
  
  end

  cstruct ofp_flow_removed {
    uint64_t cookie;
    uint16_t priority;
    uint8_t reason;
    uint8_t table_id;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint64_t packet_count;
    uint64_t byte_count
  } as big_endian

  type t = flowRemoved

  let sizeof (f : flowRemoved) : int =
    sizeof_ofp_flow_removed + (OfpMatch.sizeof f.oxm)

  let to_string (f : flowRemoved) : string =
   Format.sprintf "{ cookie = %Lu; priotity = %u; reason = %s; table_id = %u;\
   duration s/ns = %lu/%lu; idle_timeout = %s; hard_timeout = %s; packet_count = %Lu;\
   byte_count = %Lu; match = %s }"
   f.cookie
   f.priority
   (Reason.to_string f.reason)
   f.table_id
   f.duration_sec
   f.duration_nsec
   (match f.idle_timeout with
      | Permanent -> "Permanent"
      | ExpiresAfter t-> string_of_int t)
   (match f.hard_timeout with
      | Permanent -> "Permanent"
      | ExpiresAfter t-> string_of_int t)
   f.packet_count
   f.byte_count
   (OfpMatch.to_string f.oxm)

   let marshal (buf : Cstruct.t) (f : flowRemoved) : int =
     set_ofp_flow_removed_cookie buf f.cookie;
     set_ofp_flow_removed_priority buf f.priority;
     set_ofp_flow_removed_reason buf (Reason.marshal f.reason);
     set_ofp_flow_removed_table_id buf f.table_id;
     set_ofp_flow_removed_duration_sec buf f.duration_sec;
     set_ofp_flow_removed_duration_nsec buf f.duration_nsec;
     set_ofp_flow_removed_idle_timeout buf (match f.idle_timeout with
                                              | Permanent -> 0
                                              | ExpiresAfter v -> v);
     set_ofp_flow_removed_hard_timeout buf (match f.hard_timeout with
                                              | Permanent -> 0
                                              | ExpiresAfter v -> v);
     set_ofp_flow_removed_packet_count buf f.packet_count;
     set_ofp_flow_removed_byte_count buf f.byte_count;
     let oxm_buf = Cstruct.shift buf sizeof_ofp_flow_removed in
     sizeof_ofp_flow_removed + (OfpMatch.marshal oxm_buf f.oxm)

   let parse (bits : Cstruct.t) : flowRemoved = 
     let cookie = get_ofp_flow_removed_cookie bits in
     let priority = get_ofp_flow_removed_priority bits in
     let reason = Reason.parse (get_ofp_flow_removed_reason bits) in
     let table_id = get_ofp_flow_removed_table_id bits in
     let duration_sec = get_ofp_flow_removed_duration_sec bits in
     let duration_nsec = get_ofp_flow_removed_duration_nsec bits in
     let idle_timeout = match (get_ofp_flow_removed_idle_timeout bits) with
                         | 0 -> Permanent 
                         | n -> ExpiresAfter n in
     let hard_timeout = match (get_ofp_flow_removed_hard_timeout bits) with
                         | 0 -> Permanent 
                         | n -> ExpiresAfter n in
     let packet_count = get_ofp_flow_removed_packet_count bits in
     let byte_count = get_ofp_flow_removed_byte_count bits in
     let oxm,_ = OfpMatch.parse (Cstruct.shift bits sizeof_ofp_flow_removed) in
     { cookie; priority; reason; table_id; duration_sec; duration_nsec; idle_timeout;
       hard_timeout; packet_count; byte_count; oxm }
     

end


(* Multipart Messages*)

module FlowRequest = OpenFlow0x04.FlowRequest

module TableFeatures = OpenFlow0x04.TableFeatures

module QueueRequest = OpenFlow0x04.QueueRequest

module QueueDescReq = struct

  cstruct ofp_queue_desc_request {
    uint32_t port_no;
    uint32_t queue_id
  } as big_endian
  
  type t = queueDescRequest

  let sizeof ( _ : t) =
    sizeof_ofp_queue_desc_request

  let to_string (t : t) = 
    Format.sprintf "{ port_no = %s; queue_id = %lu }"
    (PseudoPort.to_string t.port_no)
    t.queue_id

  let marshal (buf : Cstruct.t) (t : t) : int =
    set_ofp_queue_desc_request_port_no buf (PseudoPort.marshal t.port_no);
    set_ofp_queue_desc_request_queue_id buf t.queue_id;
    sizeof_ofp_queue_desc_request

  let parse (bits : Cstruct.t) : t =
    let port_no = PseudoPort.make (get_ofp_queue_desc_request_port_no bits) 0 in
    let queue_id = get_ofp_queue_desc_request_queue_id bits in 
    {port_no; queue_id}

end

module FlowMonitorRequest = struct

  cstruct ofp_flow_monitor_request {
    uint32_t monitor_id;
    uint32_t out_port;
    uint32_t out_group;
    uint16_t flags;
    uint8_t table_id;
    uint8_t command
  } as big_endian

  module Command = struct

    cenum ofp_flow_monitor_command {
      OFPFMC_ADD = 0;
      OFPFMC_MODIFY = 1;
      OFPFMC_DELETE = 2
    } as uint8_t

    let to_string (t : flowMonitorCommand) =
      match t with
        | FMonAdd -> "Add"
        | FMonModify -> "Modify"
        | FMonDelete -> "Delete"

    let marshal (t : flowMonitorCommand) = 
      match t with
        | FMonAdd -> ofp_flow_monitor_command_to_int OFPFMC_ADD
        | FMonModify -> ofp_flow_monitor_command_to_int OFPFMC_MODIFY
        | FMonDelete -> ofp_flow_monitor_command_to_int OFPFMC_DELETE

    let parse bits : flowMonitorCommand = 
      match int_to_ofp_flow_monitor_command bits with
        | Some OFPFMC_ADD -> FMonAdd
        | Some OFPFMC_MODIFY -> FMonModify
        | Some OFPFMC_DELETE -> FMonDelete
        | None -> raise (Unparsable (sprintf "malformed command"))

  end

  module Flags = struct
    let marshal (f : flowMonitorFlags) = 
      (if f.fmInitial then 1 lsl 0 else 0) lor
        (if f.fmAdd then 1 lsl 1 else 0) lor
         (if f.fmRemoved then 1 lsl 2 else 0) lor
          (if f.fmModify then 1 lsl 3 else 0) lor
           (if f.fmInstructions then 1 lsl 4 else 0) lor
            (if f.fmNoAbvrev then 1 lsl 5 else 0) lor
             (if f.fmOnlyOwn then 1 lsl 6 else 0)

    let parse bits : flowMonitorFlags = 
      { fmInitial = test_bit16 0 bits
      ; fmAdd = test_bit16 1 bits
      ; fmRemoved = test_bit16 2 bits
      ; fmModify = test_bit16 3 bits
      ; fmInstructions = test_bit16 4 bits
      ; fmNoAbvrev = test_bit16 5 bits
      ; fmOnlyOwn = test_bit16 6 bits}

    let to_string (f : flowMonitorFlags) = 
      Format.sprintf "{ initial = %B; add = %B; removed = %B; modify = %B; instructions = %B\
                        no_abbrev = %B; only_own = %B }"
      f.fmInitial
      f.fmAdd
      f.fmRemoved
      f.fmModify
      f.fmInstructions
      f.fmNoAbvrev
      f.fmOnlyOwn
  end
  
  type t = flowMonitorReq

  let sizeof (t : t) = 
    sizeof_ofp_flow_monitor_request +  (OfpMatch.sizeof t.fmMatch)

  let to_string (t : t) = 
    Format.sprintf "{ monitor_id = %lu; out_port = %s; out_group = %lu; flags = %s\
                      table_id = %u; command = %s; match = %s }"
    t.fmMonitor_id
    (PseudoPort.to_string t.fmOut_port)
    t.fmOut_group
    (Flags.to_string t.fmFlags)
    t.fmTable_id
    (Command.to_string t.fmCommand)
    (OfpMatch.to_string t.fmMatch)

  let marshal (buf : Cstruct.t) (t : t) : int =
    set_ofp_flow_monitor_request_monitor_id buf t.fmMonitor_id;
    set_ofp_flow_monitor_request_out_port buf (PseudoPort.marshal t.fmOut_port);
    set_ofp_flow_monitor_request_out_group buf t.fmOut_group;
    set_ofp_flow_monitor_request_flags buf (Flags.marshal t.fmFlags);
    set_ofp_flow_monitor_request_table_id buf t.fmTable_id;
    set_ofp_flow_monitor_request_command buf (Command.marshal t.fmCommand);
    sizeof_ofp_flow_monitor_request + (OfpMatch.marshal (Cstruct.shift buf sizeof_ofp_flow_monitor_request) t.fmMatch)

  let parse (bits : Cstruct.t) : t = 
    { fmMonitor_id = get_ofp_flow_monitor_request_monitor_id bits
    ; fmOut_port = PseudoPort.make (get_ofp_flow_monitor_request_out_port bits) 0
    ; fmOut_group = get_ofp_flow_monitor_request_out_group bits
    ; fmFlags = Flags.parse (get_ofp_flow_monitor_request_flags bits)
    ; fmTable_id = get_ofp_flow_monitor_request_table_id bits
    ; fmCommand = Command.parse (get_ofp_flow_monitor_request_command bits)
    ; fmMatch = (let ret,_ = OfpMatch.parse (Cstruct.shift bits sizeof_ofp_flow_monitor_request) in ret)
    }
end

cenum ofp_multipart_types {
  OFPMP_DESC = 0;
  OFPMP_FLOW = 1;
  OFPMP_AGGREGATE = 2;
  OFPMP_TABLE = 3;
  OFPMP_PORT_STATS = 4;
  OFPMP_QUEUE = 5;
  OFPMP_GROUP = 6;
  OFPMP_GROUP_DESC = 7;
  OFPMP_GROUP_FEATURES = 8;
  OFPMP_METER = 9;
  OFPMP_METER_CONFIG = 10;
  OFPMP_METER_FEATURES = 11;
  OFPMP_TABLE_FEATURES = 12;
  OFPMP_PORT_DESC = 13;
  OFPMP_TABLE_DESC = 14;
  OFPMP_QUEUE_DESC = 15;
  OFPMP_FLOW_MONITOR = 16;
  OFPMP_EXPERIMENTER = 0xffff
} as uint16_t

module MultipartReq = struct

  cstruct ofp_multipart_request {
    uint16_t typ; (* One of the OFPMP_* constants. *)
    uint16_t flags; (* OFPMPF_REQ_* flags. *)
    uint8_t pad0;
    uint8_t pad1;
    uint8_t pad2;
    uint8_t pad3
  } as big_endian

  cenum ofp_multipart_request_flags {
    OFPMPF_REQ_MORE = 1 (* More requests to follow. *)
  } as uint16_t

  cstruct ofp_experimenter_multipart_header {
    uint32_t experimenter;
    uint32_t exp_type
  } as big_endian

  cstruct ofp_port_stats_request {
    uint32_t port_no;
    uint8_t pad[4]
  } as big_endian

  cstruct ofp_group_stats_request {
    uint32_t group_id;
    uint8_t pad[4]
  } as big_endian

  cstruct ofp_meter_multipart_request {
    uint32_t meter_id;
    uint8_t pad[4]
  } as big_endian

  type t = multipartRequest

  let msg_code_of_request mpr = match mpr with
    | SwitchDescReq -> OFPMP_DESC
    | PortsDescReq -> OFPMP_PORT_DESC
    | FlowStatsReq _ -> OFPMP_FLOW
    | AggregFlowStatsReq _ -> OFPMP_AGGREGATE
    | TableStatsReq -> OFPMP_TABLE
    | PortStatsReq _ -> OFPMP_PORT_STATS
    | QueueStatsReq _ -> OFPMP_QUEUE
    | GroupStatsReq _ -> OFPMP_GROUP
    | GroupDescReq -> OFPMP_GROUP_DESC
    | GroupFeatReq -> OFPMP_GROUP_FEATURES
    | MeterStatsReq _ -> OFPMP_METER
    | MeterConfReq _ -> OFPMP_METER_CONFIG
    | MeterFeatReq -> OFPMP_METER_FEATURES
    | TableFeatReq _ -> OFPMP_TABLE_FEATURES
    | ExperimentReq _ -> OFPMP_EXPERIMENTER
    | TableDescReq -> OFPMP_TABLE_DESC
    | QueueDescReq _ -> OFPMP_QUEUE_DESC
    | FlowMonitorReq _ -> OFPMP_FLOW_MONITOR

  let sizeof (mpr : multipartRequest) =
    sizeof_ofp_multipart_request + 
    (match mpr.mpr_type with 
       | SwitchDescReq | PortsDescReq | TableStatsReq | MeterFeatReq | GroupDescReq
       | GroupFeatReq
       | TableDescReq -> 0
       | FlowStatsReq fr -> FlowRequest.sizeof fr 
       | AggregFlowStatsReq fr -> FlowRequest.sizeof fr
       | PortStatsReq _ -> sizeof_ofp_port_stats_request 
       | QueueStatsReq q -> QueueRequest.sizeof q
       | GroupStatsReq _ -> sizeof_ofp_group_stats_request 
       | MeterStatsReq _  | MeterConfReq _ -> sizeof_ofp_meter_multipart_request
       | QueueDescReq q -> QueueDescReq.sizeof q
       | TableFeatReq tfr -> (match tfr with
          | None -> 0
          | Some t -> TableFeatures.sizeof t)
       | FlowMonitorReq f -> FlowMonitorRequest.sizeof f
       | ExperimentReq _ -> sizeof_ofp_experimenter_multipart_header )

  let to_string (mpr : multipartRequest) : string =
    Format.sprintf "{ more = %B; typ = %s }"
    mpr.mpr_flags
    (match mpr.mpr_type with
      | SwitchDescReq -> "SwitchDesc Req"
      | PortsDescReq -> "PortDesc Req"
      | FlowStatsReq f -> 
          Format.sprintf "FlowStats Req %s" (FlowRequest.to_string f)
      | AggregFlowStatsReq f -> 
          Format.sprintf "AggregFlowStats %s Req" (FlowRequest.to_string f)
      | TableStatsReq -> "TableStats Req"
      | PortStatsReq p -> 
          Format.sprintf "PortStats Req %lu" p
      | QueueStatsReq q -> 
          Format.sprintf "QueueStats Req %s" (QueueRequest.to_string q)
      | GroupStatsReq g -> Format.sprintf "GroupStats Req %lu" g
      | GroupDescReq -> "GroupDesc Req"
      | GroupFeatReq -> "GroupFeat Req"
      | MeterStatsReq m -> Format.sprintf "MeterStats Req %lu " m
      | MeterConfReq m -> Format.sprintf "MeterConf Req %lu" m
      | MeterFeatReq -> "MeterFeat Req"
      | TableFeatReq t -> Format.sprintf "TableFeat Req %s" (match t with
        | Some v -> TableFeatures.to_string v
        | None -> "None" )
      | ExperimentReq e-> Format.sprintf "Experimenter Req: id: %lu; type: %lu" e.experimenter e.exp_typ
      | TableDescReq -> "TableDesc Req" 
      | QueueDescReq q -> QueueDescReq.to_string q
      | FlowMonitorReq f -> FlowMonitorRequest.to_string f)

  let marshal (buf : Cstruct.t) (mpr : multipartRequest) : int =
    let size = sizeof_ofp_multipart_request in
    set_ofp_multipart_request_typ buf (ofp_multipart_types_to_int (msg_code_of_request mpr.mpr_type));
    set_ofp_multipart_request_flags buf (
      match mpr.mpr_flags with
        | true -> ofp_multipart_request_flags_to_int OFPMPF_REQ_MORE
        | false -> 0);
    set_ofp_multipart_request_pad0 buf 0;
    set_ofp_multipart_request_pad1 buf 0;
    set_ofp_multipart_request_pad2 buf 0;
    set_ofp_multipart_request_pad3 buf 0;
    let pay_buf = Cstruct.shift buf sizeof_ofp_multipart_request in
    match mpr.mpr_type with
      | SwitchDescReq
      | PortsDescReq -> size
      | FlowStatsReq f -> size + (FlowRequest.marshal pay_buf f)
      | AggregFlowStatsReq f -> size + (FlowRequest.marshal pay_buf f)
      | TableStatsReq -> size
      | PortStatsReq p -> set_ofp_port_stats_request_port_no pay_buf p;
                          size + sizeof_ofp_port_stats_request
      | QueueStatsReq q -> size + (QueueRequest.marshal pay_buf q)
      | GroupStatsReq g -> set_ofp_port_stats_request_port_no pay_buf g;
                           size + sizeof_ofp_port_stats_request
      | GroupDescReq
      | GroupFeatReq -> size
      | MeterStatsReq m -> set_ofp_meter_multipart_request_meter_id pay_buf m;
                           size + sizeof_ofp_meter_multipart_request
      | MeterConfReq m -> set_ofp_meter_multipart_request_meter_id pay_buf m;
                          size + sizeof_ofp_meter_multipart_request
      | MeterFeatReq -> size
      | TableFeatReq t -> 
        (match t with
          | None -> 0
          | Some v -> size + (TableFeatures.marshal pay_buf v))
      | ExperimentReq _ -> size
      | TableDescReq -> size
      | QueueDescReq q -> size + (QueueDescReq.marshal pay_buf q)
      | FlowMonitorReq f -> size + (FlowMonitorRequest.marshal pay_buf f)

  let parse (bits : Cstruct.t) : multipartRequest =
    let mprType = int_to_ofp_multipart_types (get_ofp_multipart_request_typ bits) in
    let mpr_flags = (
      match int_to_ofp_multipart_request_flags (get_ofp_multipart_request_flags bits) with
        | Some OFPMPF_REQ_MORE -> true
        | _ -> false) in
    let mpr_type = match mprType with
      | Some OFPMP_DESC -> SwitchDescReq
      | Some OFPMP_PORT_DESC -> PortsDescReq
      | Some OFPMP_FLOW -> FlowStatsReq (
        FlowRequest.parse (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_AGGREGATE -> AggregFlowStatsReq (
        FlowRequest.parse (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_TABLE -> TableStatsReq
      | Some OFPMP_PORT_STATS -> PortStatsReq (
        get_ofp_port_stats_request_port_no (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_QUEUE -> QueueStatsReq (
        QueueRequest.parse (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_GROUP -> GroupStatsReq (
        get_ofp_group_stats_request_group_id (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_GROUP_DESC -> GroupDescReq
      | Some OFPMP_GROUP_FEATURES -> GroupFeatReq
      | Some OFPMP_METER -> MeterStatsReq (
        get_ofp_meter_multipart_request_meter_id (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_METER_CONFIG -> MeterConfReq (
        get_ofp_meter_multipart_request_meter_id (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_METER_FEATURES -> MeterFeatReq
      | Some OFPMP_TABLE_FEATURES -> TableFeatReq (
      if Cstruct.len bits <= sizeof_ofp_multipart_request then None
      else Some (
        TableFeatures.parse (Cstruct.shift bits sizeof_ofp_multipart_request)
      ))
      | Some OFPMP_EXPERIMENTER -> ExperimentReq (
      let exp_bits = Cstruct.shift bits sizeof_ofp_multipart_request in
      let exp_id = get_ofp_experimenter_multipart_header_experimenter exp_bits in
      let exp_type = get_ofp_experimenter_multipart_header_exp_type exp_bits in
      {experimenter = exp_id; exp_typ = exp_type})
      | Some OFPMP_TABLE_DESC -> TableDescReq
      | Some OFPMP_QUEUE_DESC -> QueueDescReq (QueueDescReq.parse (Cstruct.shift bits sizeof_ofp_multipart_request))
      | Some OFPMP_FLOW_MONITOR -> FlowMonitorReq (FlowMonitorRequest.parse (Cstruct.shift bits sizeof_ofp_multipart_request))
      | _ -> raise (Unparsable (sprintf "bad ofp_multipart_types number"))
    in {mpr_type; mpr_flags}


end

module FlowStats = OpenFlow0x04.FlowStats

module AggregateStats = OpenFlow0x04.AggregateStats

module TableStats = OpenFlow0x04.TableStats

module PortStats = struct

  cstruct ofp_port_stats {
    uint16_t length;
    uint8_t pad[2];
    uint32_t port_no;
    uint32_t duration_sec;
    uint32_t duration_nsec;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint64_t rx_errors;
    uint64_t tx_errors;
  } as big_endian

  module Properties = struct

    cenum ofp_port_stats_prop_type {
      OFPPSPT_ETHERNET = 0;
      OFPPSPT_OPTICAL = 1;
      OFPPSPT_EXPERIMENTER = 0xffff
    } as uint16_t

    module Ethernet = struct
      cstruct ofp_port_stats_prop_ethernet {
        uint16_t typ;
        uint16_t len;
        uint8_t pad[4];
        uint64_t rx_frame_err;
        uint64_t rx_over_err;
        uint64_t rx_crc_err;
        uint64_t collisions
      } as big_endian

      type t = portStatsPropEthernet

      let to_string (t : t) =
        Format.sprintf "{ rx_frame_err = %Lu; rx_over_err = %Lu; rx_crc_err = %Lu; collisions = %Lu }"
        t.rx_frame_err
        t.rx_over_err
        t.rx_crc_err
        t.collisions

      let sizeof (_ : t) = 
        sizeof_ofp_port_stats_prop_ethernet

      let marshal (buf : Cstruct.t) (t : t) : int =
        set_ofp_port_stats_prop_ethernet_typ buf (ofp_port_stats_prop_type_to_int OFPPSPT_ETHERNET);
        set_ofp_port_stats_prop_ethernet_len buf sizeof_ofp_port_stats_prop_ethernet;
        set_ofp_port_stats_prop_ethernet_rx_frame_err buf t.rx_frame_err;
        set_ofp_port_stats_prop_ethernet_rx_over_err buf t.rx_over_err;
        set_ofp_port_stats_prop_ethernet_rx_crc_err buf t.rx_crc_err;
        set_ofp_port_stats_prop_ethernet_collisions buf t.collisions;
        sizeof_ofp_port_stats_prop_ethernet

      let parse (bits : Cstruct.t) : t =
        { rx_frame_err = get_ofp_port_stats_prop_ethernet_rx_frame_err bits
        ; rx_over_err = get_ofp_port_stats_prop_ethernet_rx_over_err bits
        ; rx_crc_err = get_ofp_port_stats_prop_ethernet_rx_crc_err bits
        ; collisions = get_ofp_port_stats_prop_ethernet_collisions bits }

    end

    module Optical = struct

      module Flags = struct

        type t = portStatsOpticalFlag

        let to_string (t : t) = 
          Format.sprintf "{ rx_tune = %B; tx_tune = %B; tx_pwr = %B; rx_pwr = %B;\
                            tx_bias = %B; tx_temp = %B }"
          t.rx_tune
          t.tx_tune
          t.tx_pwr
          t.rx_pwr
          t.tx_bias
          t.tx_temp

        let marshal (t : t) : int32 = 
          Int32.logor (if t.rx_tune then (Int32.shift_left 1l 0) else 0l)
            (Int32.logor (if t.tx_tune then (Int32.shift_left 1l 1) else 0l)
              (Int32.logor (if t.tx_pwr then (Int32.shift_left 1l 2) else 0l)
                (Int32.logor (if t.rx_pwr then (Int32.shift_left 1l 4) else 0l)
                  (Int32.logor (if t.tx_bias then (Int32.shift_left 1l 5) else 0l)
                    (if t.tx_temp then (Int32.shift_left 1l 6) else 0l)))))

        let parse bits : t =
          { rx_tune = Bits.test_bit 0 bits
          ; tx_tune = Bits.test_bit 1 bits
          ; tx_pwr = Bits.test_bit 2 bits
          ; rx_pwr = Bits.test_bit 4 bits
          ; tx_bias = Bits.test_bit 5 bits
          ; tx_temp = Bits.test_bit 6 bits }

      end
      cstruct ofp_port_stats_prop_optical {
        uint16_t typ;
        uint16_t len;
        uint8_t pad[4];
        uint32_t flags;
        uint32_t tx_freq_lmda;
        uint32_t tx_offset;
        uint32_t tx_grid_span;
        uint32_t rx_freq_lmda;
        uint32_t rx_offset;
        uint32_t rx_grid_span;
        uint16_t tx_pwr;
        uint16_t rx_pwr;
        uint16_t bias_current;
        uint16_t temperature
      } as big_endian

      type t = portStatsPropOptical

      let sizeof (_ : t) =
        sizeof_ofp_port_stats_prop_optical

      let to_string (t : t) = 
        Format.sprintf "{ flags = %s; tx_freq_lmda = %lu; tx_offset = %lu; tx_grid_span = %lu;\
        rx_freq_lmda = %lu; rx_offset = %lu; rx_grid_span = %lu; \
        tx_pwr = %u; rx_pwr = %u; bias_current = %u; temperature = %u }"
        (Flags.to_string t.flags)
        t.tx_freq_lmda
        t.tx_offset
        t.tx_grid_span
        t.rx_freq_lmda
        t.rx_offset
        t.rx_grid_span
        t.tx_pwr
        t.rx_pwr
        t.bias_current
        t.temperature

      let marshal (buf : Cstruct.t) (t : t) : int =
        set_ofp_port_stats_prop_optical_typ buf (ofp_port_stats_prop_type_to_int OFPPSPT_OPTICAL);
        set_ofp_port_stats_prop_optical_len buf sizeof_ofp_port_stats_prop_optical;
        set_ofp_port_stats_prop_optical_flags buf (Flags.marshal t.flags);
        set_ofp_port_stats_prop_optical_tx_freq_lmda buf t.tx_freq_lmda;
        set_ofp_port_stats_prop_optical_tx_offset buf t.tx_offset;
        set_ofp_port_stats_prop_optical_tx_grid_span buf t.tx_grid_span;
        set_ofp_port_stats_prop_optical_rx_freq_lmda buf t.rx_freq_lmda;
        set_ofp_port_stats_prop_optical_rx_offset buf t.rx_offset;
        set_ofp_port_stats_prop_optical_rx_grid_span buf t.rx_grid_span;
        set_ofp_port_stats_prop_optical_tx_pwr buf t.tx_pwr;
        set_ofp_port_stats_prop_optical_rx_pwr buf t.rx_pwr;
        set_ofp_port_stats_prop_optical_bias_current buf t.bias_current;
        set_ofp_port_stats_prop_optical_temperature buf t.temperature;
        sizeof_ofp_port_stats_prop_optical

      let parse (bits : Cstruct.t) : t =
        { flags = Flags.parse (get_ofp_port_stats_prop_optical_flags bits)
        ; tx_freq_lmda = get_ofp_port_stats_prop_optical_tx_freq_lmda bits
        ; tx_offset =  get_ofp_port_stats_prop_optical_tx_offset bits
        ; tx_grid_span = get_ofp_port_stats_prop_optical_tx_grid_span bits
        ; rx_freq_lmda = get_ofp_port_stats_prop_optical_rx_freq_lmda bits
        ; rx_offset =  get_ofp_port_stats_prop_optical_rx_offset bits
        ; rx_grid_span = get_ofp_port_stats_prop_optical_rx_grid_span bits
        ; tx_pwr = get_ofp_port_stats_prop_optical_tx_pwr bits
        ; rx_pwr = get_ofp_port_stats_prop_optical_rx_pwr bits
        ; bias_current = get_ofp_port_stats_prop_optical_bias_current bits
        ; temperature = get_ofp_port_stats_prop_optical_temperature bits
        }

    end

    module Experimenter = struct

      cstruct ofp_port_stats_prop_experimenter {
        uint16_t typ;
        uint16_t len;
        uint32_t experimenter;
        uint32_t exp_typ
      } as big_endian

      type t = experimenter

      let to_string (t : t) : string =
        Format.sprintf "{ experimenter : %lu; exp_typ : %lu }"
         t.experimenter
         t.exp_typ

      let sizeof ( _ : t ) =
        sizeof_ofp_port_stats_prop_experimenter

      let marshal (buf : Cstruct.t) (t : t) : int =
        set_ofp_port_stats_prop_experimenter_typ buf (ofp_port_stats_prop_type_to_int OFPPSPT_EXPERIMENTER);
        set_ofp_port_stats_prop_experimenter_len buf sizeof_ofp_port_stats_prop_experimenter;
        set_ofp_port_stats_prop_experimenter_experimenter buf t.experimenter;
        set_ofp_port_stats_prop_experimenter_exp_typ buf t.exp_typ;
        sizeof_ofp_port_stats_prop_experimenter

      let parse (bits : Cstruct.t) : t =
        { experimenter = get_ofp_port_stats_prop_experimenter_experimenter bits
        ; exp_typ = get_ofp_port_stats_prop_experimenter_exp_typ bits}

    end

    cstruct ofp_port_stats_prop_header {
      uint16_t typ;
      uint16_t len;
    } as big_endian

    type t = portStatsProp

    let sizeof (t : t) : int =
      match t with 
        | PortStatsPropEthernet p -> Ethernet.sizeof p
        | PortStatsPropOptical p -> Optical.sizeof p
        | PortStatsPropExperimenter p -> Experimenter.sizeof p

    let to_string (t : t) : string = 
      match t with 
        | PortStatsPropEthernet p -> Format.sprintf "Ethernet : %s" (Ethernet.to_string p)
        | PortStatsPropOptical p -> Format.sprintf "Optical : %s" (Optical.to_string p)
        | PortStatsPropExperimenter p -> Format.sprintf "Experimenter : %s" (Experimenter.to_string p)

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_port_stats_prop_header then None
      else Some (get_ofp_port_stats_prop_header_len buf)

    let marshal (buf : Cstruct.t) (t : t) =
      match t with
        | PortStatsPropEthernet p -> Ethernet.marshal buf p
        | PortStatsPropOptical p -> Optical.marshal buf p
        | PortStatsPropExperimenter p -> Experimenter.marshal buf p

    let parse (bits : Cstruct.t) : t =
      let typ = match int_to_ofp_port_stats_prop_type (get_ofp_port_stats_prop_header_typ bits) with
        | Some v -> v
        | None -> raise (Unparsable (sprintf "malformed prop typ")) in
      match typ with 
        | OFPPSPT_ETHERNET -> PortStatsPropEthernet (Ethernet.parse bits)
        | OFPPSPT_OPTICAL -> PortStatsPropOptical (Optical.parse bits)
        | OFPPSPT_EXPERIMENTER -> PortStatsPropExperimenter (Experimenter.parse bits)


  end

  type t = portStats

  let sizeof (ps : portStats) = 
    sizeof_ofp_port_stats + sum (map Properties.sizeof ps.properties)
  
  let to_string ps =
    Format.sprintf "{ port_no = %lu; duration (s/ns) = %lu/%lu ;rx/tx pkt = %Lu/%Lu;\
                      rx/tx byt = %Lu/%Lu; rx/tx dropped = %Lu/%Lu; rx/tx error = %Lu/%Lu;
                      properties : %s  }"
    ps.psPort_no
    ps.duration_sec
    ps.duration_nsec
    ps.rx_packets
    ps.tx_packets
    ps.rx_bytes
    ps.tx_bytes
    ps.rx_dropped
    ps.tx_dropped
    ps.rx_errors
    ps.tx_errors
    ("[ " ^ (String.concat "; " (map Properties.to_string ps.properties)) ^ " ]")

  let marshal (buf : Cstruct.t) (ps : portStats) : int =
    set_ofp_port_stats_length buf (sizeof ps);
    set_ofp_port_stats_port_no buf ps.psPort_no;
    set_ofp_port_stats_duration_sec buf ps.duration_sec;
    set_ofp_port_stats_duration_nsec buf ps.duration_nsec;
    set_ofp_port_stats_rx_packets buf ps.rx_packets;
    set_ofp_port_stats_tx_packets buf ps.tx_packets;
    set_ofp_port_stats_rx_bytes buf ps.rx_bytes;
    set_ofp_port_stats_tx_bytes buf ps.tx_bytes;
    set_ofp_port_stats_rx_dropped buf ps.rx_dropped;
    set_ofp_port_stats_tx_dropped buf ps.tx_dropped;
    set_ofp_port_stats_rx_errors buf ps.rx_errors;
    set_ofp_port_stats_tx_errors buf ps.tx_errors;
    sizeof_ofp_port_stats + marshal_fields (Cstruct.shift buf sizeof_ofp_port_stats) ps.properties Properties.marshal

  let parse (bits : Cstruct.t) : portStats =
    { psPort_no     = get_ofp_port_stats_port_no bits;
      duration_sec  = get_ofp_port_stats_duration_sec bits;
      duration_nsec = get_ofp_port_stats_duration_nsec bits;
      rx_packets    = get_ofp_port_stats_rx_packets bits;
      tx_packets    = get_ofp_port_stats_tx_packets bits;
      rx_bytes      = get_ofp_port_stats_rx_bytes bits;
      tx_bytes      = get_ofp_port_stats_tx_bytes bits;
      rx_dropped    = get_ofp_port_stats_rx_dropped bits;
      tx_dropped    = get_ofp_port_stats_tx_dropped bits;
      rx_errors     = get_ofp_port_stats_rx_errors bits;
      tx_errors     = get_ofp_port_stats_tx_errors bits;
      properties    = parse_fields (Cstruct.shift bits sizeof_ofp_port_stats) Properties.parse Properties.length_func
    }

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_port_stats then None
    else Some (get_ofp_port_stats_length buf)

end 

module QueueStats = struct

  module Properties = struct

    cstruct ofp_queue_stats_prop_header {
      uint16_t typ;
      uint16_t len
    } as big_endian

    cenum ofp_queue_stats_prop_type {
      OFPQSPT_EXPERIMENTER = 0xffff
    } as uint16_t

    module Experimenter = struct
      cstruct ofp_queue_stats_prop_experimenter {
        uint16_t typ;
        uint16_t len;
        uint32_t experimenter;
        uint32_t exp_typ
      } as big_endian

      type t = experimenter

      let to_string (t : t) : string =
        Format.sprintf "{ experimenter : %lu; exp_typ : %lu }"
         t.experimenter
         t.exp_typ

      let sizeof ( _ : t ) =
        sizeof_ofp_queue_stats_prop_experimenter

      let marshal (buf : Cstruct.t) (t : t) : int =
        set_ofp_queue_stats_prop_experimenter_typ buf (ofp_queue_stats_prop_type_to_int OFPQSPT_EXPERIMENTER);
        set_ofp_queue_stats_prop_experimenter_len buf sizeof_ofp_queue_stats_prop_experimenter;
        set_ofp_queue_stats_prop_experimenter_experimenter buf t.experimenter;
        set_ofp_queue_stats_prop_experimenter_exp_typ buf t.exp_typ;
        sizeof_ofp_queue_stats_prop_experimenter

      let parse (bits : Cstruct.t) : t =
        { experimenter = get_ofp_queue_stats_prop_experimenter_experimenter bits
        ; exp_typ = get_ofp_queue_stats_prop_experimenter_exp_typ bits}

    end

    type t = queueStatsProp

    let sizeof (t : t) : int =
      match t with
        | ExperimenterQueueStats e -> Experimenter.sizeof e

    let to_string (t : t) : string =
      match t with
        | ExperimenterQueueStats e -> Format.sprintf "Experimenter : %s" (Experimenter.to_string e)

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_queue_stats_prop_header then None
      else Some (get_ofp_queue_stats_prop_header_len buf)

    let marshal (buf : Cstruct.t) (t : t) =
      match t with
        | ExperimenterQueueStats e -> Experimenter.marshal buf e

    let parse (bits : Cstruct.t) : t =
      let typ = match int_to_ofp_queue_stats_prop_type (get_ofp_queue_stats_prop_header_typ bits) with
        | Some v -> v
        | None -> raise (Unparsable (sprintf "malformed prop typ")) in
      match typ with
        | OFPQSPT_EXPERIMENTER -> ExperimenterQueueStats (Experimenter.parse bits)
  end

  cstruct ofp_queue_stats {
    uint16_t length;
    uint8_t pad[6];
    uint32_t port_no;
    uint32_t queue_id;
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errors;
    uint32_t duration_sec;
    uint32_t duration_nsec
  } as big_endian

  type t = queueStats

  let sizeof (qs : queueStats) : int =
    sizeof_ofp_queue_stats + sum (map Properties.sizeof qs.properties)

  let to_string (qs : queueStats) : string =
    Format.sprintf "{ port no = %lu; queue_id = %lu; tx bytes = %Lu; tx pkt = %Lu; tx errors = %Lu; duration (s/ns) = %lu/%lu;\
                      properties = %s }"
    qs.qsPort_no
    qs.queue_id
    qs.tx_bytes
    qs.tx_packets
    qs.tx_errors
    qs.duration_sec
    qs.duration_nsec
    ("[ " ^ (String.concat "; " (map Properties.to_string qs.properties)) ^ " ]")

  let marshal (buf : Cstruct.t) (qs : queueStats) : int = 
    set_ofp_queue_stats_length buf (sizeof qs);
    set_ofp_queue_stats_port_no buf qs.qsPort_no;
    set_ofp_queue_stats_queue_id buf qs.queue_id;
    set_ofp_queue_stats_tx_bytes buf qs.tx_bytes;
    set_ofp_queue_stats_tx_packets buf qs.tx_packets;
    set_ofp_queue_stats_tx_errors buf qs.tx_errors;
    set_ofp_queue_stats_duration_sec buf qs.duration_sec;
    set_ofp_queue_stats_duration_nsec buf qs.duration_nsec;
    sizeof_ofp_queue_stats + marshal_fields (Cstruct.shift buf sizeof_ofp_queue_stats) qs.properties Properties.marshal

  let parse (bits : Cstruct.t) : queueStats =
    { qsPort_no = get_ofp_queue_stats_port_no bits
    ; queue_id = get_ofp_queue_stats_queue_id bits
    ; tx_bytes = get_ofp_queue_stats_tx_bytes bits
    ; tx_packets = get_ofp_queue_stats_tx_packets bits
    ; tx_errors = get_ofp_queue_stats_tx_errors bits
    ; duration_sec = get_ofp_queue_stats_duration_sec bits
    ; duration_nsec = get_ofp_queue_stats_duration_nsec bits
    ; properties = parse_fields (Cstruct.shift bits sizeof_ofp_queue_stats) Properties.parse Properties.length_func
    }

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_queue_stats then None
    else Some (get_ofp_queue_stats_length buf)
end

module GroupStats = OpenFlow0x04.GroupStats

module GroupDesc = OpenFlow0x04.GroupDesc

module GroupFeatures = OpenFlow0x04.GroupFeatures

module MeterStats = OpenFlow0x04.MeterStats

module MeterConfig = OpenFlow0x04.MeterConfig

module MeterFeaturesStats = OpenFlow0x04.MeterFeaturesStats

module SwitchDescriptionReply = OpenFlow0x04.SwitchDescriptionReply

module TableDescReply = struct

  cstruct ofp_table_desc {
    uint16_t len;
    uint8_t table_id;
    uint8_t pad;
    uint32_t config
  } as big_endian

  type t = tableDescReply

  let sizeof (tab : t) : int =
    sizeof_ofp_table_desc + sum (map TableMod.Properties.sizeof tab.properties)

  let to_string (tab : t) : string =
    Format.sprintf "{ tabled_id = %u; config = %s; properties = %s }"
    tab.table_id
    (TableMod.TableConfig.to_string tab.config)
    ("[ " ^ (String.concat "; " (map TableMod.Properties.to_string tab.properties))^ " ]")

  let marshal (buf : Cstruct.t) (tab : t) : int =
    set_ofp_table_desc_len buf (sizeof tab);
    set_ofp_table_desc_table_id buf tab.table_id;
    set_ofp_table_desc_config buf (TableMod.TableConfig.marshal tab.config);
    sizeof_ofp_table_desc + (marshal_fields (Cstruct.shift buf sizeof_ofp_table_desc) tab.properties TableMod.Properties.marshal)

  let parse (bits : Cstruct.t) : t =
    let table_id = get_ofp_table_desc_table_id bits in
    let config = TableMod.TableConfig.parse (get_ofp_table_desc_config bits) in
    let properties = parse_fields (Cstruct.shift bits sizeof_ofp_table_desc) TableMod.Properties.parse TableMod.Properties.length_func in
    { table_id; config; properties }

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_table_desc then None
    else Some (get_ofp_table_desc_len buf)

end

module QueueDescReply  = struct

  module Properties = struct

    cenum ofp_queue_desc_prop_type {
      OFPQDPT_MIN_RATE = 1;
      OFPQDPT_MAX_RATE = 2;
      OFPQDPT_EXPERIMENTER = 0xffff
    } as uint16_t

    module MinRate = struct

      cstruct ofp_queue_desc_prop_min_rate {
        uint16_t typ;
        uint16_t len;
        uint16_t rate;
        uint8_t pad[2]
      } as big_endian

      type t = rateQueue

      let sizeof (_ : t) =
        sizeof_ofp_queue_desc_prop_min_rate

      let to_string (t : t) = 
        match t with
          | Rate n -> string_of_int n
          | Disabled -> "Disabled"

      let marshal (buf : Cstruct.t) (t : t) =
        set_ofp_queue_desc_prop_min_rate_typ buf (ofp_queue_desc_prop_type_to_int OFPQDPT_MIN_RATE);
        set_ofp_queue_desc_prop_min_rate_len buf sizeof_ofp_queue_desc_prop_min_rate;
        set_ofp_queue_desc_prop_min_rate_rate buf (
          match t with 
            | Rate n -> n
            | Disabled -> 0xffff);
        sizeof_ofp_queue_desc_prop_min_rate

      let parse (bits : Cstruct.t) : t = 
        let rate = get_ofp_queue_desc_prop_min_rate_rate bits in
        if rate > 1000 then Disabled
        else Rate rate

    end

    module MaxRate = struct

      cstruct ofp_queue_desc_prop_max_rate {
        uint16_t typ;
        uint16_t len;
        uint16_t rate;
        uint8_t pad[2]
      } as big_endian

      type t = rateQueue

      let sizeof (_ : t) =
        sizeof_ofp_queue_desc_prop_max_rate

      let to_string (t : t) = 
        match t with
          | Rate n -> string_of_int n
          | Disabled -> "Disabled"

      let marshal (buf : Cstruct.t) (t : t) =
        set_ofp_queue_desc_prop_max_rate_typ buf (ofp_queue_desc_prop_type_to_int OFPQDPT_MAX_RATE);
        set_ofp_queue_desc_prop_max_rate_len buf sizeof_ofp_queue_desc_prop_max_rate;
        set_ofp_queue_desc_prop_max_rate_rate buf (
          match t with 
            | Rate n -> n
            | Disabled -> 0xffff);
        sizeof_ofp_queue_desc_prop_max_rate

      let parse (bits : Cstruct.t) : t = 
        let rate = get_ofp_queue_desc_prop_max_rate_rate bits in
        if rate > 1000 then Disabled
        else Rate rate

    end

    module Experimenter = struct

      cstruct ofp_queue_desc_prop_experimenter {
        uint16_t typ;
        uint16_t len;
        uint32_t experimenter;
        uint32_t exp_typ      
      } as big_endian

      type t = experimenter

      let sizeof (_ : t) : int =
        sizeof_ofp_queue_desc_prop_experimenter

      let to_string (t : t) : string = 
        Format.sprintf "{ experimenter = %lu; exp_typ = %lu }"
        t.experimenter
        t.exp_typ

      let marshal (buf : Cstruct.t) (t : t) : int = 
        set_ofp_queue_desc_prop_experimenter_typ buf (ofp_queue_desc_prop_type_to_int OFPQDPT_EXPERIMENTER);
        set_ofp_queue_desc_prop_experimenter_len buf (sizeof t);
        set_ofp_queue_desc_prop_experimenter_experimenter buf t.experimenter;
        set_ofp_queue_desc_prop_experimenter_exp_typ buf t.exp_typ;
        sizeof_ofp_queue_desc_prop_experimenter

      let parse (bits : Cstruct.t) : t =
        { experimenter = get_ofp_queue_desc_prop_experimenter_experimenter bits
        ; exp_typ = get_ofp_queue_desc_prop_experimenter_exp_typ bits}

    end
    cstruct ofp_queue_desc_prop_header {
      uint16_t typ;
      uint16_t len;
    } as  big_endian

    type t = queueDescProp

    let sizeof (t : t) =
      match t with
        | QueueDescPropMinRate r -> MinRate.sizeof r
        | QueueDescPropMaxRate r -> MaxRate.sizeof r
        | QueueDescPropExperimenter e -> Experimenter.sizeof e

    let to_string (t : t) = 
      match t with
        | QueueDescPropMinRate r -> Format.sprintf "MinRate : %s" (MinRate.to_string r)
        | QueueDescPropMaxRate r -> Format.sprintf "MaxRate : %s" (MaxRate.to_string r)
        | QueueDescPropExperimenter e -> Format.sprintf "Experimenter : %s" (Experimenter.to_string e)

    let marshal (buf : Cstruct.t) (t : t) : int =
      match t with
        | QueueDescPropMinRate r -> MinRate.marshal buf r
        | QueueDescPropMaxRate r -> MaxRate.marshal buf r
        | QueueDescPropExperimenter e -> Experimenter.marshal buf e

    let parse (bits : Cstruct.t) : t =
      match int_to_ofp_queue_desc_prop_type (get_ofp_queue_desc_prop_header_typ bits) with
        | Some OFPQDPT_MIN_RATE -> QueueDescPropMinRate (MinRate.parse bits)
        | Some OFPQDPT_MAX_RATE -> QueueDescPropMaxRate (MaxRate.parse bits)
        | Some OFPQDPT_EXPERIMENTER -> QueueDescPropExperimenter (Experimenter.parse bits)
        | None -> raise (Unparsable (sprintf "Malformed queue desc prop typ"))

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_queue_desc_prop_header then None
      else Some (get_ofp_queue_desc_prop_header_len buf)

  end

  cstruct ofp_queue_desc {
    uint32_t port_no;
    uint32_t queue_id;
    uint16_t len;
    uint8_t pad[6]
  } as big_endian

  type t = queueDescReply

  let sizeof (t : t) =
    sizeof_ofp_queue_desc + sum (map Properties.sizeof t.properties)

  let to_string (t : t) = 
    Format.sprintf "{ port_no = %lu; queue_id = %lu; properties = %s }"
    t.port_no
    t.queue_id
    ("[ " ^ (String.concat "; " (map Properties.to_string t.properties)) ^ " ]")

  let marshal (buf : Cstruct.t) (t : t) : int =
    set_ofp_queue_desc_port_no buf t.port_no;
    set_ofp_queue_desc_queue_id buf t.queue_id;
    set_ofp_queue_desc_len buf (sizeof t);
    sizeof_ofp_queue_desc + marshal_fields (Cstruct.shift buf sizeof_ofp_queue_desc) t.properties Properties.marshal

  let parse (bits : Cstruct.t) : t =
    { port_no = get_ofp_queue_desc_port_no bits
    ; queue_id = get_ofp_queue_desc_queue_id bits
    ; properties = parse_fields (Cstruct.shift bits sizeof_ofp_queue_desc) Properties.parse Properties.length_func
    }

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_queue_desc then None
    else Some (get_ofp_queue_desc_len buf)
end

module FlowMonitorReply = struct

  cenum ofp_flow_update_event {
    OFPFME_INITIAL = 0;
    OFPFME_ADDED = 1;
    OFPFME_REMOVED = 2;
    OFPFME_MODIFIED = 3;
    OFPFME_ABBREV = 4;
    OFPFME_PAUSED = 5;
    OFPFME_RESUMED = 6
  } as uint16_t

  module UpdateFull = struct

    cstruct ofp_flow_update_full {
      uint16_t length;
      uint16_t event;
      uint8_t table_id;
      uint8_t reason;
      uint16_t idle_timeout;
      uint16_t hard_timeout;
      uint16_t priority;
      uint8_t zeros[4];
      uint64_t cookie;
    } as big_endian

    type t = fmUpdateFull

    let sizeof (t : t) =
      sizeof_ofp_flow_update_full + (OfpMatch.sizeof t.updateMatch)+ (Instructions.sizeof t.instructions)

    let to_string (t : t) = 
      Format.sprintf "{ event = %s; table_id = %u; reason = %s; idle_timeout = %s; hard_timeout = %s\
                        priority = %u; cookie = %Lu; match = %s; instructions = %s }"
      (match t.event with
        | InitialUpdate -> "Initial"
        | AddedUpdate -> "Added"
        | RemovedUpdate -> "Remove"
        | ModifiedUpdate -> "Modified")
      t.table_id
      (FlowRemoved.Reason.to_string t.reason)
      (match t.idle_timeout with
       | Permanent -> "Permanent"
       | ExpiresAfter v -> string_of_int v)
      (match t.hard_timeout with
       | Permanent -> "Permanent"
       | ExpiresAfter v -> string_of_int v)
      t.priority
      t.cookie
      (OfpMatch.to_string t.updateMatch)
      (Instructions.to_string t.instructions)

    let marshal (buf : Cstruct.t) (t : t) =
      set_ofp_flow_update_full_length buf (sizeof t);
      set_ofp_flow_update_full_event buf (
        match t.event with
          | InitialUpdate -> ofp_flow_update_event_to_int OFPFME_INITIAL
          | AddedUpdate -> ofp_flow_update_event_to_int OFPFME_ADDED
          | RemovedUpdate -> ofp_flow_update_event_to_int OFPFME_REMOVED
          | ModifiedUpdate -> ofp_flow_update_event_to_int OFPFME_MODIFIED);
      set_ofp_flow_update_full_table_id buf t.table_id;
      set_ofp_flow_update_full_reason buf (FlowRemoved.Reason.marshal t.reason);
      set_ofp_flow_update_full_idle_timeout buf (
        match t.idle_timeout with
          | Permanent -> 0
          | ExpiresAfter n -> n);
      set_ofp_flow_update_full_hard_timeout buf (
        match t.hard_timeout with
          | Permanent -> 0
          | ExpiresAfter n -> n);
      set_ofp_flow_update_full_priority buf t.priority;
      set_ofp_flow_update_full_cookie buf t.cookie;
      let size = sizeof_ofp_flow_update_full +
        OfpMatch.marshal 
         (Cstruct.sub buf sizeof_ofp_flow_update_full (OfpMatch.sizeof t.updateMatch))
         t.updateMatch in
      size + Instructions.marshal (Cstruct.shift buf size) t.instructions

    let parse (bits : Cstruct.t) (e : updateEvent): t =
      let event = e in
      let table_id = get_ofp_flow_update_full_table_id bits in
      let reason = FlowRemoved.Reason.parse (get_ofp_flow_update_full_reason bits) in
      let idle_timeout = (
        match get_ofp_flow_update_full_idle_timeout bits with 
          | 0 -> Permanent
          | n -> ExpiresAfter n) in
      let hard_timeout = (
        match get_ofp_flow_update_full_hard_timeout bits with
          | 0 -> Permanent
          | n -> ExpiresAfter n) in
      let priority = get_ofp_flow_update_full_priority bits in
      let cookie = get_ofp_flow_update_full_cookie bits in
      let updateMatch,instructionsBits = OfpMatch.parse (Cstruct.shift bits sizeof_ofp_flow_update_full) in
      let instructions = Instructions.parse instructionsBits in
      { event; table_id; reason; idle_timeout; hard_timeout; priority; cookie; updateMatch; instructions }

    let length_func (buf : Cstruct.t) : int option = 
      if Cstruct.len buf < sizeof_ofp_flow_update_full then None
      else Some (get_ofp_flow_update_full_length buf)

  end

  module Abbrev = struct

    cstruct ofp_flow_update_abbrev {
      uint16_t len;
      uint16_t event;
      uint32_t xid
    } as big_endian

    type t = int32 

    let sizeof _ =
      sizeof_ofp_flow_update_abbrev

    let to_string t = 
      Format.sprintf "{ xid = %lu }" t

    let marshal (buf : Cstruct.t) (t : t) =
      set_ofp_flow_update_abbrev_len buf sizeof_ofp_flow_update_abbrev;
      set_ofp_flow_update_abbrev_event buf (ofp_flow_update_event_to_int OFPFME_ABBREV);
      set_ofp_flow_update_abbrev_xid buf t;
      sizeof_ofp_flow_update_abbrev

    let parse (bits : Cstruct.t) : t =
      get_ofp_flow_update_abbrev_xid bits

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_flow_update_abbrev then None
      else Some sizeof_ofp_flow_update_abbrev

  end

  module Paused = struct

    cstruct ofp_flow_update_paused {
      uint16_t len;
      uint16_t event;
      uint8_t zeros[4]
    } as big_endian

    type t = pauseEvent

    let sizeof _ =
      sizeof_ofp_flow_update_paused

    let to_string t =
      match t with
        | Pause -> "Pause"
        | Resume -> "Resume"

    let marshal (buf : Cstruct.t) (t : t) =
      set_ofp_flow_update_paused_len buf sizeof_ofp_flow_update_paused;
      set_ofp_flow_update_paused_event buf (
        match t with
          | Pause -> ofp_flow_update_event_to_int OFPFME_PAUSED
          | Resume -> ofp_flow_update_event_to_int OFPFME_RESUMED);
      sizeof_ofp_flow_update_paused

    let length_func (buf : Cstruct.t) : int option =
      if Cstruct.len buf < sizeof_ofp_flow_update_paused then None
      else Some (get_ofp_flow_update_paused_len buf)

  end

  cstruct ofp_flow_update_header {
    uint16_t len;
    uint16_t event;
  } as big_endian

  type t = flowMonitorReply

  let sizeof (t : t) =
    match t with
      | FmUpdateFull u -> UpdateFull.sizeof u
      | FmAbbrev a -> Abbrev.sizeof a
      | FmPaused p -> Paused.sizeof p

  let to_string (t : t) = 
    match t with
      | FmUpdateFull u -> UpdateFull.to_string u
      | FmAbbrev a -> Format.sprintf "Abbrev : %s" (Abbrev.to_string a)
      | FmPaused p -> Paused.to_string p

  let marshal (buf : Cstruct.t) (t : t) = 
    match t with
      | FmUpdateFull u -> UpdateFull.marshal buf u
      | FmAbbrev a -> Abbrev.marshal buf a
      | FmPaused p -> Paused.marshal buf p

  let parse (bits : Cstruct.t) : t =
    match int_to_ofp_flow_update_event (get_ofp_flow_update_header_event bits) with
      | Some OFPFME_INITIAL -> FmUpdateFull (UpdateFull.parse bits InitialUpdate)
      | Some OFPFME_ADDED -> FmUpdateFull (UpdateFull.parse bits AddedUpdate)
      | Some OFPFME_REMOVED -> FmUpdateFull (UpdateFull.parse bits RemovedUpdate)
      | Some OFPFME_MODIFIED -> FmUpdateFull (UpdateFull.parse bits ModifiedUpdate)
      | Some OFPFME_ABBREV -> FmAbbrev (Abbrev.parse bits)
      | Some OFPFME_PAUSED -> FmPaused Pause
      | Some OFPFME_RESUMED -> FmPaused Resume
      | None -> raise (Unparsable (sprintf "malformed event"))

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_flow_update_header then None
    else Some (get_ofp_flow_update_header_len buf)
end

module MultipartReply = struct

  cstruct ofp_multipart_reply {
    uint16_t typ;
    uint16_t flags;
    uint8_t pad[4];
    uint8_t body[0]
  } as big_endian

  cenum ofp_multipart_reply_flags {
    OFPMPF_REPLY_MORE = 1 (* More requests to follow. *)
  } as uint16_t

  type t = multipartReply

  let sizeof (mpr : multipartReply) =
    sizeof_ofp_multipart_reply +
    match mpr.mpreply_typ with
      | PortsDescReply pdr -> sum (map PortDesc.sizeof pdr)
      | SwitchDescReply s -> SwitchDescriptionReply.sizeof s
      | FlowStatsReply fsr -> sum (map FlowStats.sizeof fsr)
      | AggregateReply ag -> AggregateStats.sizeof ag
      | TableReply tr -> sum (map TableStats.sizeof tr)
      | TableFeaturesReply tf -> TableFeatures.sizeof tf
      | PortStatsReply psr -> sum (map PortStats.sizeof psr)
      | QueueStatsReply qsr -> sum (map QueueStats.sizeof qsr)
      | GroupStatsReply gs -> sum (map GroupStats.sizeof gs)
      | GroupDescReply gd -> sum (map GroupDesc.sizeof gd)
      | GroupFeaturesReply gf -> GroupFeatures.sizeof gf
      | MeterReply mr -> sum (map MeterStats.sizeof mr)
      | MeterConfig mc -> sum (map MeterConfig.sizeof mc)
      | MeterFeaturesReply mf -> MeterFeaturesStats.sizeof mf
      | TableDescReply t -> sum (map TableDescReply.sizeof t)
      | QueueDescReply q -> sum (map QueueDescReply.sizeof q)
      | FlowMonitorReply f -> sum (map FlowMonitorReply.sizeof f)

  let to_string (mpr : multipartReply) =
    match mpr.mpreply_typ with
      | PortsDescReply pdr -> Format.sprintf "PortsDescReply { %s }" (String.concat "; " (map PortDesc.to_string pdr))
      | SwitchDescReply sdc -> Format.sprintf "SwitchDescReply %s" (SwitchDescriptionReply.to_string sdc)
      | FlowStatsReply fsr -> Format.sprintf "Flow { %s }" (String.concat "; " (map FlowStats.to_string fsr))
      | AggregateReply ag -> Format.sprintf "Aggregate Flow %s" (AggregateStats.to_string ag)
      | TableReply tr -> Format.sprintf "TableReply { %s }" (String.concat "; " (map TableStats.to_string tr))
      | TableFeaturesReply tf -> Format.sprintf "TableFeaturesReply %s" (TableFeatures.to_string tf)
      | PortStatsReply psr -> Format.sprintf "PortStatsReply { %s }" (String.concat "; " (map PortStats.to_string psr))
      | QueueStatsReply qsr -> Format.sprintf "QueueStats { %s }" (String.concat "; " (map QueueStats.to_string qsr))
      | GroupStatsReply gs -> Format.sprintf "GroupStats { %s }" (String.concat "; " (map GroupStats.to_string gs))
      | GroupDescReply gd -> Format.sprintf "GroupSDesc { %s }" (String.concat "; " (map GroupDesc.to_string gd))
      | GroupFeaturesReply gf -> Format.sprintf "GroupFeatures %s" (GroupFeatures.to_string gf)
      | MeterReply mr -> Format.sprintf "MeterStats { %s }" (String.concat "; " (map MeterStats.to_string mr))
      | MeterConfig mc -> Format.sprintf "MeterConfig { %s }" (String.concat "; " (map MeterConfig.to_string mc))
      | MeterFeaturesReply mf -> Format.sprintf "MeterFeaturesStats %s" (MeterFeaturesStats.to_string mf)
      | TableDescReply t -> Format.sprintf "TableDescReply { %s }" (String.concat "; " (map TableDescReply.to_string t))
      | QueueDescReply q -> Format.sprintf "QueueDescReply { %s }" (String.concat "; " (map QueueDescReply.to_string q))
      | FlowMonitorReply f -> Format.sprintf "FlowMonitorReply { %s }" (String.concat "; " (map FlowMonitorReply.to_string f))

  let marshal (buf : Cstruct.t) (mpr : multipartReply) : int =
    let ofp_body_bits = Cstruct.shift buf sizeof_ofp_multipart_reply in
    set_ofp_multipart_reply_flags buf (
      match mpr.mpreply_flags with
        | true -> ofp_multipart_reply_flags_to_int OFPMPF_REPLY_MORE
        | false -> 0);
    sizeof_ofp_multipart_reply + (match mpr.mpreply_typ with
      | PortsDescReply pdr -> 
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_PORT_DESC);
          marshal_fields ofp_body_bits pdr PortDesc.marshal
      | SwitchDescReply sdr -> 
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_DESC);
          SwitchDescriptionReply.marshal ofp_body_bits sdr
      | FlowStatsReply fsr -> 
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_FLOW);
          marshal_fields ofp_body_bits fsr FlowStats.marshal
      | AggregateReply ar -> 
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_AGGREGATE);
          AggregateStats.marshal ofp_body_bits ar
      | TableReply tr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_TABLE);
          marshal_fields ofp_body_bits tr TableStats.marshal
      | TableFeaturesReply tf ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_TABLE_FEATURES);
          TableFeatures.marshal ofp_body_bits tf
      | PortStatsReply psr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_PORT_STATS);
          marshal_fields ofp_body_bits psr PortStats.marshal
      | QueueStatsReply qsr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_QUEUE);
          marshal_fields ofp_body_bits qsr QueueStats.marshal
      | GroupStatsReply gs ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_GROUP);
          marshal_fields ofp_body_bits gs GroupStats.marshal
      | GroupDescReply gd ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_GROUP_DESC);
          marshal_fields ofp_body_bits gd GroupDesc.marshal
      | GroupFeaturesReply gf ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_GROUP_FEATURES);
          GroupFeatures.marshal ofp_body_bits gf
      | MeterReply mr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_METER);
          marshal_fields ofp_body_bits mr MeterStats.marshal
      | MeterConfig mc ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_METER_CONFIG);
          marshal_fields ofp_body_bits mc MeterConfig.marshal
      | MeterFeaturesReply mfr ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_METER_FEATURES);
          MeterFeaturesStats.marshal ofp_body_bits mfr
      | TableDescReply t ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_TABLE_DESC);
          marshal_fields ofp_body_bits t TableDescReply.marshal
      | QueueDescReply q ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_QUEUE_DESC);
          marshal_fields ofp_body_bits q QueueDescReply.marshal
      | FlowMonitorReply f ->
          set_ofp_multipart_reply_typ buf (ofp_multipart_types_to_int OFPMP_FLOW_MONITOR);
          marshal_fields ofp_body_bits f FlowMonitorReply.marshal
          )
    
  let parse (bits : Cstruct.t) : multipartReply =
    let ofp_body_bits = Cstruct.shift bits sizeof_ofp_multipart_reply in
    let typ = (match int_to_ofp_multipart_types (get_ofp_multipart_reply_typ bits) with
      | Some OFPMP_PORT_DESC -> 
          PortsDescReply (parse_fields ofp_body_bits PortDesc.parse PortDesc.length_func)
      | Some OFPMP_DESC -> 
          SwitchDescReply (SwitchDescriptionReply.parse ofp_body_bits)
      | Some OFPMP_FLOW -> 
          FlowStatsReply (parse_fields ofp_body_bits FlowStats.parse FlowStats.length_func)
      | Some OFPMP_AGGREGATE -> 
          AggregateReply (AggregateStats.parse ofp_body_bits)
      | Some OFPMP_TABLE -> 
          TableReply (parse_fields ofp_body_bits TableStats.parse TableStats.length_func)
      | Some OFPMP_TABLE_FEATURES ->
          TableFeaturesReply (TableFeatures.parse ofp_body_bits)
      | Some OFPMP_PORT_STATS -> 
          PortStatsReply (parse_fields ofp_body_bits PortStats.parse PortStats.length_func)
      | Some OFPMP_QUEUE ->
          QueueStatsReply (parse_fields ofp_body_bits QueueStats.parse QueueStats.length_func)
      | Some OFPMP_GROUP ->
          GroupStatsReply (parse_fields ofp_body_bits GroupStats.parse GroupStats.length_func)
      | Some OFPMP_GROUP_DESC ->
          GroupDescReply (parse_fields ofp_body_bits GroupDesc.parse GroupDesc.length_func)
      | Some OFPMP_GROUP_FEATURES ->
          GroupFeaturesReply (GroupFeatures.parse ofp_body_bits)
      | Some OFPMP_METER ->
          MeterReply (parse_fields ofp_body_bits MeterStats.parse MeterStats.length_func)
      | Some OFPMP_METER_CONFIG ->
          MeterConfig (parse_fields ofp_body_bits MeterConfig.parse MeterConfig.length_func)
      | Some OFPMP_METER_FEATURES ->
          MeterFeaturesReply (MeterFeaturesStats.parse ofp_body_bits)
      | Some OFPMP_QUEUE_DESC ->
          QueueDescReply (parse_fields ofp_body_bits QueueDescReply.parse QueueDescReply.length_func)
      | Some OFPMP_TABLE_DESC ->
          TableDescReply (parse_fields ofp_body_bits TableDescReply.parse TableDescReply.length_func)
      | Some OFPMP_FLOW_MONITOR ->
          FlowMonitorReply (parse_fields ofp_body_bits FlowMonitorReply.parse FlowMonitorReply.length_func)
      | _ -> raise (Unparsable (sprintf "NYI: can't parse this multipart reply"))) in
    let flags = (
      match int_to_ofp_multipart_reply_flags (get_ofp_multipart_reply_flags bits) with
        | Some OFPMPF_REPLY_MORE -> true
        | _ -> false) in
    {mpreply_typ = typ; mpreply_flags = flags}

end

module PacketOut = OpenFlow0x04.PacketOut

module RoleRequest = OpenFlow0x04.RoleRequest

module BundleProp = struct

  cenum ofp_bundle_prop_type {
    OFPBPT_EXPERIMENTER = 0xFFFF
  } as uint16_t

  cstruct ofp_bundle_prop_header {
    uint16_t typ;
    uint16_t len
  } as big_endian
  
  module Experimenter = struct
    cstruct ofp_bundle_prop_experimenter {
      uint16_t typ;
      uint16_t len;
      uint32_t experimenter;
      uint32_t exp_typ
    } as big_endian

    type t = experimenter

    let to_string (t : t) : string =
      Format.sprintf "{ experimenter : %lu; exp_typ : %lu }"
       t.experimenter
       t.exp_typ

    let sizeof ( _ : t ) =
      sizeof_ofp_bundle_prop_experimenter

    let marshal (buf : Cstruct.t) (t : t) : int =
      set_ofp_bundle_prop_experimenter_typ buf (ofp_bundle_prop_type_to_int OFPBPT_EXPERIMENTER);
      set_ofp_bundle_prop_experimenter_len buf sizeof_ofp_bundle_prop_experimenter;
      set_ofp_bundle_prop_experimenter_experimenter buf t.experimenter;
      set_ofp_bundle_prop_experimenter_exp_typ buf t.exp_typ;
      sizeof_ofp_bundle_prop_experimenter

    let parse (bits : Cstruct.t) : t =
      { experimenter = get_ofp_bundle_prop_experimenter_experimenter bits
      ; exp_typ = get_ofp_bundle_prop_experimenter_exp_typ bits}

  end

  type t  = bundleProp

  let sizeof (t : t) : int =
    match t with
      | BundleExperimenter e -> Experimenter.sizeof e

  let to_string (t : t) : string =
    match t with
      | BundleExperimenter e -> Format.sprintf "Experimenter : %s" (Experimenter.to_string e)

  let length_func (buf : Cstruct.t) : int option =
    if Cstruct.len buf < sizeof_ofp_bundle_prop_header then None
    else Some (get_ofp_bundle_prop_header_len buf)

  let marshal (buf : Cstruct.t) (t : t) =
    match t with
      | BundleExperimenter e -> Experimenter.marshal buf e

  let parse (bits : Cstruct.t) : t =
    let typ = match int_to_ofp_bundle_prop_type (get_ofp_bundle_prop_header_typ bits) with
      | Some v -> v
      | None -> raise (Unparsable (sprintf "malformed prop typ")) in
    match typ with
      | OFPBPT_EXPERIMENTER -> BundleExperimenter (Experimenter.parse bits)
end

module BundleFlags = struct

  type t = bundleFlags

  let to_string (t : t) = 
    Format.sprintf "{ atomic = %B; ordered = %B }"
    t.atomic
    t.ordered

  let marshal (f : t) =
    (if f.atomic then 1 lsl 0 else 0) lor
      (if f.ordered then 1 lsl 1 else 0)

  let parse bits : t =
    { atomic = test_bit16  0 bits
    ; ordered = test_bit16  1 bits }

end

module BundleCtrl = struct

  cstruct ofp_bundle_ctrl_msg {
    uint32_t bundle_id;
    uint16_t typ;
    uint16_t flags
  } as big_endian

  cenum ofp_bundle_ctrl_type {
    OFPBCT_OPEN_REQUEST = 0;
    OFPBCT_OPEN_REPLY = 1;
    OFPBCT_CLOSE_REQUEST = 2;
    OFPBCT_CLOSE_REPLY = 3;
    OFPBCT_COMMIT_REQUEST = 4;
    OFPBCT_COMMIT_REPLY = 5;
    OFPBCT_DISCARD_REQUEST = 6;
    OFPBCT_DISCARD_REPLY = 7
  } as uint16_t

  type t = bundleCtrl

  let sizeof (t : t) =
    sizeof_ofp_bundle_ctrl_msg + sum (map BundleProp.sizeof t.properties)

  let to_string (t : t) =
    Format.sprintf "{ bundle_id = %lu; typ = %s; flags = %s; properties = %s }"
    t.bundle_id
    (match t.typ with
      | OpenReq -> "OpenReq"
      | OpenReply -> "OpenReply"
      | CloseReq -> "CloseReq"
      | CloseReply -> "CloseReply"
      | CommitReq -> "CommitReq"
      | CommitReply -> "CommitReply"
      | DiscardReq -> "DiscardReq"
      | DiscardReply -> "DiscardReply")
    (BundleFlags.to_string t.flags)
    ("[ " ^ (String.concat "; " (map BundleProp.to_string t.properties)) ^ " ]")

  let marshal (buf : Cstruct.t) (t : t) =
    set_ofp_bundle_ctrl_msg_bundle_id buf t.bundle_id;
    set_ofp_bundle_ctrl_msg_typ buf (
      match t.typ with
        | OpenReq -> ofp_bundle_ctrl_type_to_int OFPBCT_OPEN_REQUEST
        | OpenReply -> ofp_bundle_ctrl_type_to_int OFPBCT_OPEN_REPLY
        | CloseReq -> ofp_bundle_ctrl_type_to_int OFPBCT_CLOSE_REQUEST
        | CloseReply -> ofp_bundle_ctrl_type_to_int OFPBCT_CLOSE_REPLY
        | CommitReq -> ofp_bundle_ctrl_type_to_int OFPBCT_COMMIT_REQUEST
        | CommitReply -> ofp_bundle_ctrl_type_to_int OFPBCT_COMMIT_REPLY
        | DiscardReq -> ofp_bundle_ctrl_type_to_int OFPBCT_DISCARD_REQUEST
        | DiscardReply -> ofp_bundle_ctrl_type_to_int OFPBCT_DISCARD_REPLY);
    set_ofp_bundle_ctrl_msg_flags buf (BundleFlags.marshal t.flags);
    sizeof_ofp_bundle_ctrl_msg + marshal_fields (Cstruct.shift buf sizeof_ofp_bundle_ctrl_msg) t.properties BundleProp.marshal

  let parse (bits : Cstruct.t) : t =
    { bundle_id = get_ofp_bundle_ctrl_msg_bundle_id bits
    ; typ = (match int_to_ofp_bundle_ctrl_type (get_ofp_bundle_ctrl_msg_typ bits) with
              | Some OFPBCT_OPEN_REQUEST -> OpenReq
              | Some OFPBCT_OPEN_REPLY -> OpenReply
              | Some OFPBCT_CLOSE_REQUEST -> CloseReq
              | Some OFPBCT_CLOSE_REPLY -> CloseReply
              | Some OFPBCT_COMMIT_REQUEST -> CommitReq
              | Some OFPBCT_COMMIT_REPLY -> CommitReply
              | Some OFPBCT_DISCARD_REQUEST -> DiscardReq
              | Some OFPBCT_DISCARD_REPLY -> DiscardReply
              | None -> raise (Unparsable (sprintf "malformed bundle controle type")))
    ; flags = BundleFlags.parse (get_ofp_bundle_ctrl_msg_flags bits)
    ; properties = parse_fields (Cstruct.shift bits sizeof_ofp_bundle_ctrl_msg) BundleProp.parse BundleProp.length_func
    }

end

module BundleAdd = struct

  cstruct ofp_bundle_add_msg {
    uint32_t bundle_id;
    uint16_t pad;
    uint16_t flags
  } as big_endian

(*  type t = 'a bundleAdd*)

  module Header = OpenFlow_Header

  let sizeof (t : 'a bundleAdd) (sizeof_fn : 'a -> int)=
    sizeof_ofp_bundle_add_msg + (sizeof_fn t.message) + sum (map BundleProp.sizeof t.properties)

  let to_string (t : 'a bundleAdd) (to_string_fn : 'a -> string)=
    Format.sprintf "{ bundle_id = %lu; flags = %s; message = %s; properties = %s }"
    t.bundle_id
    (BundleFlags.to_string t.flags)
    (to_string_fn t.message)
    ("[ " ^ (String.concat "; " (map BundleProp.to_string t.properties)) ^ " ]")

  let marshal (buf : Cstruct.t) (t : 'a bundleAdd) (marshal_fn : 'a -> Cstruct.t -> int)= 
    set_ofp_bundle_add_msg_bundle_id buf t.bundle_id;
    set_ofp_bundle_add_msg_flags buf (BundleFlags.marshal t.flags);
    let body_buf = Cstruct.shift buf sizeof_ofp_bundle_add_msg in
    let message_size = marshal_fn t.message body_buf in
    let prop_buf = (Cstruct.shift body_buf message_size) in
    sizeof_ofp_bundle_add_msg + message_size + marshal_fields prop_buf t.properties BundleProp.marshal

  let parse (bits : Cstruct.t) (parse_fn : Header.t -> string -> xid * 'a) (sizeof_fn : 'a -> int) : 'a bundleAdd =
    let bundle_id = get_ofp_bundle_add_msg_bundle_id bits in
    let flags = BundleFlags.parse (get_ofp_bundle_add_msg_flags bits) in
    let message_bits = Cstruct.shift bits (sizeof_ofp_bundle_add_msg + Header.size) in
    let hdr = Header.parse (Cstruct.shift bits (sizeof_ofp_bundle_add_msg)) in
    let _,message = parse_fn hdr (Cstruct.to_string message_bits) in
    let sizeof_msg = sizeof_fn message in
    let properties = parse_fields (Cstruct.shift message_bits sizeof_msg) BundleProp.parse BundleProp.length_func in
    { bundle_id; flags; message; properties }

end


module Message = struct

  type t =
    | Hello
    | EchoRequest of bytes
    | EchoReply of bytes
    | Experimenter of Experimenter.t
    | FeaturesRequest
    | FeaturesReply of SwitchFeatures.t
    | GetConfigRequestMsg of SwitchConfig.t
    | GetConfigReplyMsg of SwitchConfig.t
    | SetConfigMsg of SwitchConfig.t
    | FlowModMsg of FlowMod.t
    | GroupModMsg of GroupMod.t
    | TableModMsg of TableMod.t
    | PortModMsg of PortMod.t
    | MeterModMsg of MeterMod.t
    | MultipartReq of MultipartReq.t
    | MultipartReply of MultipartReply.t
    | BarrierRequest
    | BarrierReply
    | PacketOutMsg of PacketOut.t
    | RoleRequest of RoleRequest.t
    | RoleReply of RoleRequest.t
    | BundleControl of BundleCtrl.t
    | BundleAdd of t bundleAdd

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
    | GetConfigRequestMsg _ -> GET_CONFIG_REQ
    | GetConfigReplyMsg _ -> GET_CONFIG_RESP
    | SetConfigMsg _ -> SET_CONFIG
    | FlowModMsg _ -> FLOW_MOD
    | GroupModMsg _ -> GROUP_MOD
    | TableModMsg _ -> TABLE_MOD
    | PortModMsg _ -> PORT_MOD
    | MeterModMsg _ -> METER_MOD
    | MultipartReq _ -> MULTIPART_REQ
    | MultipartReply _ -> MULTIPART_RESP
    | BarrierRequest -> BARRIER_REQ
    | BarrierReply -> BARRIER_RESP
    | PacketOutMsg _ -> PACKET_OUT
    | RoleRequest _ -> ROLE_REQ
    | RoleReply _ -> ROLE_RESP
    | BundleControl _ -> BUNDLE_CONTROL
    | BundleAdd _ -> BUNDLE_ADD_MESSAGE

  let rec sizeof (msg : t) : int = match msg with
    | Hello -> Header.size
    | EchoRequest bytes -> Header.size + (String.length (Cstruct.to_string bytes))
    | EchoReply bytes -> Header.size + (String.length (Cstruct.to_string bytes))
    | Experimenter exp -> Header.size + (Experimenter.sizeof exp)
    | FeaturesRequest -> Header.size
    | FeaturesReply f -> Header.size + (SwitchFeatures.sizeof f)
    | GetConfigRequestMsg conf -> Header.size + SwitchConfig.sizeof conf
    | GetConfigReplyMsg conf -> Header.size + SwitchConfig.sizeof conf
    | SetConfigMsg conf -> Header.size + SwitchConfig.sizeof conf
    | FlowModMsg flow -> Header.size + FlowMod.sizeof flow
    | GroupModMsg group -> Header.size + GroupMod.sizeof group
    | TableModMsg table -> Header.size + TableMod.sizeof table
    | PortModMsg port -> Header.size + PortMod.sizeof port
    | MeterModMsg meter -> Header.size + MeterMod.sizeof meter
    | MultipartReq m -> Header.size + MultipartReq.sizeof m
    | MultipartReply m -> Header.size + MultipartReply.sizeof m
    | BarrierRequest -> Header.size
    | BarrierReply -> Header.size
    | PacketOutMsg p -> Header.size + PacketOut.sizeof p
    | RoleRequest r -> Header.size + RoleRequest.sizeof r
    | RoleReply r -> Header.size + RoleRequest.sizeof r
    | BundleControl b -> Header.size + BundleCtrl.sizeof b
    | BundleAdd b -> Header.size + BundleAdd.sizeof b sizeof

  let to_string (msg : t) : string = match msg with
    | Hello -> "Hello"
    | EchoRequest _ -> "EchoRequest"
    | EchoReply _ -> "EchoReply"
    | Experimenter _ -> "Experimenter"
    | FeaturesRequest -> "FeaturesRequest"
    | FeaturesReply _ -> "FeaturesReply"
    | GetConfigRequestMsg _ -> "GetConfigRequest"
    | GetConfigReplyMsg _ -> "GetConfigReply"
    | SetConfigMsg _ -> "SetConfig"
    | FlowModMsg _ -> "FlowMod"
    | GroupModMsg _ -> "GroupMod"
    | TableModMsg _ -> "TableMod"
    | PortModMsg _ -> "PortMod"
    | MeterModMsg _ -> "MeterMod"
    | MultipartReq _ -> "MultipartReq"
    | MultipartReply _ -> "MultipartReply"
    | BarrierRequest -> "BarrierRequest"
    | BarrierReply -> "BarrierReply"
    | PacketOutMsg _ -> "PacketOutMsg"
    | RoleRequest _ -> "RoleReq"
    | RoleReply _ -> "RoleReply"
    | BundleControl _ -> "BundleControl"
    | BundleAdd _ -> "BundleAdd"

  (* let marshal (buf : Cstruct.t) (msg : message) : int = *)
  (*   let buf2 = (Cstruct.shift buf Header.size) in *)
  (*   set_ofp_header_version buf 0x05; *)
  (*   set_ofp_header_typ buf (msg_code_to_int (msg_code_of_message msg)); *)
  (*   set_ofp_header_length buf (sizeof msg); *)

  let rec blit_message (msg : t) (out : Cstruct.t) =
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
      | GetConfigRequestMsg conf ->
        Header.size + SwitchConfig.marshal out conf
      | GetConfigReplyMsg conf ->
        Header.size + SwitchConfig.marshal out conf
      | SetConfigMsg conf ->
        Header.size + SwitchConfig.marshal out conf
      | FlowModMsg flow ->
        Header.size + FlowMod.marshal out flow
      | GroupModMsg group ->
        Header.size + GroupMod.marshal out group
      | TableModMsg table ->
        Header.size + TableMod.marshal out table
      | PortModMsg port ->
        Header.size + PortMod.marshal out port
      | MeterModMsg meter ->
        Header.size + MeterMod.marshal out meter
      | MultipartReq m ->
        Header.size + MultipartReq.marshal out m
      | MultipartReply m ->
        Header.size + MultipartReply.marshal out m
      | BarrierRequest ->
        Header.size
      | BarrierReply ->
        Header.size
      | PacketOutMsg p -> 
        Header.size + PacketOut.marshal out p
      | RoleRequest r -> 
        Header.size + RoleRequest.marshal out r
      | RoleReply r -> 
        Header.size + RoleRequest.marshal out r
      | BundleControl b ->
        Header.size + BundleCtrl.marshal out b
      | BundleAdd b ->
        Header.size + BundleAdd.marshal out b blit_message

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

  let rec parse (hdr : Header.t) (body_buf : string) : (xid * t) =
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
      | GET_CONFIG_REQ -> GetConfigRequestMsg (SwitchConfig.parse body_bits)
      | GET_CONFIG_RESP -> GetConfigReplyMsg (SwitchConfig.parse body_bits)
      | SET_CONFIG -> SetConfigMsg (SwitchConfig.parse body_bits)
      | FLOW_MOD -> FlowModMsg (FlowMod.parse body_bits)
      | GROUP_MOD -> GroupModMsg (GroupMod.parse body_bits)
      | TABLE_MOD -> TableModMsg (TableMod.parse body_bits)
      | PORT_MOD -> PortModMsg (PortMod.parse body_bits)
      | METER_MOD -> MeterModMsg (MeterMod.parse body_bits)
      | MULTIPART_REQ -> MultipartReq (MultipartReq.parse body_bits)
      | MULTIPART_RESP -> MultipartReply (MultipartReply.parse body_bits)
      | PACKET_OUT -> PacketOutMsg (PacketOut.parse body_bits)
      | ROLE_REQ -> RoleRequest (RoleRequest.parse body_bits)
      | ROLE_RESP -> RoleReply (RoleRequest.parse body_bits)
      | BUNDLE_CONTROL -> BundleControl (BundleCtrl.parse body_bits)
      | BUNDLE_ADD_MESSAGE -> BundleAdd (BundleAdd.parse body_bits parse sizeof)
      | code -> raise (Unparsable (Printf.sprintf "unexpected message type %s" (string_of_msg_code typ))) in
    (hdr.Header.xid, msg)
end

