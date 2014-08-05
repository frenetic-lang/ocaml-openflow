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

module Message = struct

  type t =
    | Hello

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

  let sizeof (msg : t) : int = match msg with
    | Hello -> Header.size


  let to_string (msg : t) : string = match msg with
    | Hello -> "Hello"


  (* let marshal (buf : Cstruct.t) (msg : message) : int = *)
  (*   let buf2 = (Cstruct.shift buf Header.size) in *)
  (*   set_ofp_header_version buf 0x04; *)
  (*   set_ofp_header_typ buf (msg_code_to_int (msg_code_of_message msg)); *)
  (*   set_ofp_header_length buf (sizeof msg); *)

  let blit_message (msg : t) (out : Cstruct.t) =
    match msg with
      | Hello ->
        Header.size
      
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
      | code -> raise (Unparsable (Printf.sprintf "unexpected message type %s" (string_of_msg_code typ))) in
    (hdr.Header.xid, msg)
end

