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

module SwitchFeatures = OpenFlow0x04.SwitchFeatures

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

(* Multipart Messages*)

module FlowRequest = OpenFlow0x04.FlowRequest

module TableFeatures = OpenFlow0x04.TableFeatures

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

module QueueRequest = struct

  cstruct ofp_queue_stats_request {
    uint32_t port_no;
    uint32_t queue_id
  } as big_endian

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

  type t = queueRequest

  let marshal (buf : Cstruct.t) (qr : t) : int =
    set_ofp_queue_stats_request_port_no buf qr.port_number;
    set_ofp_queue_stats_request_queue_id buf qr.queue_id;
    sizeof_ofp_queue_stats_request + marshal_fields (Cstruct.shift buf sizeof_ofp_queue_stats_request) qr.properties Properties.marshal

  let parse (bits : Cstruct.t) : t = 
    let portNumber = get_ofp_queue_stats_request_port_no bits in
    let queueId = get_ofp_queue_stats_request_queue_id bits in
    let properties = parse_fields (Cstruct.shift bits sizeof_ofp_queue_stats_request) Properties.parse Properties.length_func in
    { port_number = portNumber
    ; queue_id = queueId
    ; properties = properties}

  let sizeof _ = 
      sizeof_ofp_queue_stats_request

  let to_string qr =
      Format.sprintf "{ port_no = %lu; queue_id = %lu }" qr.port_number qr.queue_id

end

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
      | TableFeatReq t-> Format.sprintf "TableFeat Req %s" (match t with
        | Some v -> TableFeatures.to_string v
        | None -> "None" )
      | ExperimentReq e-> Format.sprintf "Experimenter Req: id: %lu; type: %lu" e.experimenter e.exp_typ
      | TableDescReq -> "TableDesc Req" 
      | QueueDescReq q -> QueueDescReq.to_string q)

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
      | _ -> raise (Unparsable (sprintf "bad ofp_multipart_types number"))
    in {mpr_type; mpr_flags}


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

  let sizeof (msg : t) : int = match msg with
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
      | GET_CONFIG_REQ -> GetConfigRequestMsg (SwitchConfig.parse body_bits)
      | GET_CONFIG_RESP -> GetConfigReplyMsg (SwitchConfig.parse body_bits)
      | SET_CONFIG -> SetConfigMsg (SwitchConfig.parse body_bits)
      | FLOW_MOD -> FlowModMsg (FlowMod.parse body_bits)
      | GROUP_MOD -> GroupModMsg (GroupMod.parse body_bits)
      | TABLE_MOD -> TableModMsg (TableMod.parse body_bits)
      | PORT_MOD -> PortModMsg (PortMod.parse body_bits)
      | METER_MOD -> MeterModMsg (MeterMod.parse body_bits)
      | code -> raise (Unparsable (Printf.sprintf "unexpected message type %s" (string_of_msg_code typ))) in
    (hdr.Header.xid, msg)
end

