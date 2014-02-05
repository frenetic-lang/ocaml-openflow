open Packet

type 'a mask = { m_value : 'a; m_mask : 'a option }

type switchId = int64

type portId = int16

type queueId = int32

type xid = OpenFlow_Header.xid

type portConfig =
{ down : bool (** Port is administratively down. *)
; no_stp : bool (** Disable 802.1D spanning tree on port. *)
; no_recv : bool (** Drop all packets except 802.1D spanning
                   * tree packets. *)
; no_recv_stp : bool (** Drop received 802.1D STP packets. *)
; no_flood : bool (** Do not include this port when flooding. *)
; no_fwd : bool (** Drop packets forwarded to port. *)
; no_packet_in : bool (** Do not send packet-in msgs for port. *)
}

type stpState =
  | Listen (** Not learning or relaying frames *)
  | Learn (** Learning but not relaying frames *)
  | Forward (** Learning and relaying frames *)
  | Block (** Not part of the spanning tree *)

type portState =
  { down : bool  (** No physical link present. *)
  ; stp_state : stpState (** The state of the port wrt the spanning tree
                               algorithm *)
  }

(** See the [ofp_port_features] enumeration in Section 5.2.1 of the OpenFlow
1.0 specification. *)
type portFeatures =
  { f_10MBHD : bool (** 10 Mb half-duplex rate support. *)
  ; f_10MBFD : bool (** 10 Mb full-duplex rate support. *)
  ; f_100MBHD : bool (** 100 Mb half-duplex rate support. *)
  ; f_100MBFD : bool (** 100 Mb full-duplex rate support. *)
  ; f_1GBHD : bool (** 1 Gb half-duplex rate support. *)
  ; f_1GBFD : bool (** 1 Gb full-duplex rate support. *)
  ; f_10GBFD : bool (** 10 Gb full-duplex rate support. *)
  ; copper : bool (** Copper medium. *)
  ; fiber : bool (** Fiber medium. *)
  ; autoneg : bool (** Auto-negotiation. *)
  ; pause : bool (** Pause. *)
  ; pause_asym : bool (** Asymmetric pause. *)
  }

type portDescription =
  { port_no : portId
  ; hw_addr : dlAddr
  ; name : string
  ; config : portConfig
  ; state : portState
  ; curr : portFeatures (** Current features. *)
  ; advertised : portFeatures (** Features being advertised by the port. *)
  ; supported : portFeatures (** Features supported by the port. *)
  ; peer : portFeatures (** Features advertised by peer. *)
  }

(** Fields that support wildcard patterns on this switch. *)
type supportedWildcards =
  { dlSrc : bool
  ; dlDst : bool
  ; dlTyp : bool
  ; dlVlan : bool
  ; dlVlanPcp : bool
  ; nwSrc : bool
  ; nwDst : bool
  ; nwProto : bool
  ; nwTos : bool
  ; tpSrc : bool
  ; tpDst : bool
  ; inPort : bool }

(** See the [ofp_capabilities] enumeration in Section 5.3.1 of the OpenFlow
1.0 specification. *)
type capabilities =
  { flow_stats : bool (** Flow statistics. *)
  ; table_stats : bool (** Table statistics. *)
  ; port_stats : bool (** Port statistics. *)
  ; stp : bool (** 802.1D spanning tree. *)
  ; ip_reasm : bool (** Can reassemble IP fragments. *)
  ; queue_stats : bool (** Queue statistics. *)
  ; arp_match_ip : bool (** Match IP addresses in ARP packets. *)
  }

(** Describes which actions ([Action.t]) this switch supports. *)
type supportedActions =
  { output : bool
  ; set_vlan_id : bool
  ; set_vlan_pcp : bool
  ; strip_vlan : bool
  ; set_dl_src : bool
  ; set_dl_dst : bool
  ; set_nw_src : bool
  ; set_nw_dst : bool
  ; set_nw_tos : bool
  ; set_tp_src : bool
  ; set_tp_dst : bool
  ; enqueue : bool
  ; vendor : bool }

type switchFeatures =
  { switch_id : switchId (** Datapath unique ID.  The lower 48 bits are for 
                         a MAC address, while the upper 16 bits are 
                         implementer-defined. *)
  ; num_buffers : int32 (** Max packets buffered at once. *)
  ; num_tables : int8 (** Number of tables supported by datapath. *)
  ; supported_capabilities : capabilities
  ; supported_actions : supportedActions
  ; ports : portDescription list (** Port definitions. *)
  }

type portChangeReason =
  | Add
  | Delete
  | Modify

type portStatus =
      { reason : portChangeReason
      ; desc : portDescription }

type fragFlags =
  | FragNormal 
  | FragDrop
  | FragReassemble 

type switchConfig = { 
  frag_flags : fragFlags; 
  miss_send_len : int }

type helloFailed =
  | Incompatible (** No compatible version. *)
  | Eperm (** Permissions error. *)

type badRequest =
  | BadVersion (** [Header] version not supported. *)
  | BadType (** [Message] type not supported. *)
  | BadStat (** StatsRequest type not supported. *)
  | BadVendor (** Vendor not supported. *)
  | BadSubType (** Vendor subtype not supported. *)
  | Eperm (** Permissions error. *)
  | BadLen (** Wrong request length for type. *)
  | BufferEmpty (** Specified buffer has already been used. *)
  | BufferUnknown (** Specified buffer does not exist. *)

type badAction =
  | BadType (** Unknown action type. *)
  | BadLen (** Length problem in actions. *)
  | BadVendor (** Unknown vendor id specified. *)
  | BadVendorType (** Unknown action type for vendor id. *)
  | BadOutPort (** Problem validating output action. *)
  | BadArgument (** Bad action argument. *)
  | Eperm (** Permissions error. *)
  | TooMany (** Can't handle this many actions. *)
  | BadQueue (** Problem validating output queue. *)

type flowModFailed =
  | AllTablesFull (** Flow not added because of full tables. *)
  | Overlap (** Attepted to add overlapping flow with 
            [FlowMod.check_overlap] set. *)
  | Eperm (** Permissions error. *)
  | BadEmergTimeout (** Flow not added because of non-zero idle/hard timeout. *)
  | BadCommand (** Unknown command. *)
  | Unsupported (** Unsupported action list - cannot process in the order
                specified. *)

type portModFailed =
  | BadPort (** Specified port does not exist. *)
  | BadHwAddr (** Specified hardware address is wrong. *)

type queueOpFailed =
  | BadPort (** Invalid port (or port does not exist). *)
  | BadQueue (** Queue does not exist. *)
  | Eperm (** Permissions error. *)

(** Each error is composed of a pair (error_code, data) *)
type errorCode  =
  (** Hello protocol failed. *)
  | HelloFailed of helloFailed
  (** Request was not understood. *)
  | BadRequest of badRequest
  (** Error in action description *)
  | BadAction of badAction
  (** Problem modifying flow entry. *)
  | FlowModFailed of flowModFailed
  (** Port mod request failed. *)
  | PortModFailed of portModFailed
  (** Queue operation failed. *)
  | QueueOpFailed of queueOpFailed

type error = 
  | Error of errorCode * Cstruct.t

type pattern =  
    { dlSrc : dlAddr option
    ; dlDst : dlAddr option
    ; dlTyp : dlTyp option
    ; dlVlan : dlVlan option
    ; dlVlanPcp : dlVlanPcp option
    ; nwSrc : nwAddr mask option
    ; nwDst : nwAddr mask option
    ; nwProto : nwProto option
    ; nwTos : nwTos option
    ; tpSrc : tpPort option
    ; tpDst : tpPort option
    ; inPort : portId option }

type pseudoPort =
  | PhysicalPort of portId
  | AllPorts
  | InPort
  | Flood
  | Controller of int

type action =
  | Output of pseudoPort
  | SetDlVlan of dlVlan
  | SetDlVlanPcp of dlVlanPcp
  | SetDlSrc of dlAddr
  | SetDlDst of dlAddr
  | SetNwSrc of nwAddr
  | SetNwDst of nwAddr
  | SetNwTos of nwTos
  | SetTpSrc of tpPort
  | SetTpDst of tpPort
  | Enqueue of pseudoPort * queueId

type timeout =
  | Permanent
  | ExpiresAfter of int16

type flowModCommand =
  | AddFlow
  | ModFlow
  | ModStrictFlow
  | DeleteFlow 
  | DeleteStrictFlow 

type flowMod =
    { command : flowModCommand
    ; pattern: pattern 
    ; priority : int16
    ; actions : action list
    ; cookie : int64
    ; idle_timeout : timeout
    ; hard_timeout : timeout
    ; notify_when_removed : bool
    ; apply_to_packet : int32 option
    ; out_port : pseudoPort option
    ; check_overlap : bool
    }

type payload =
  | Buffered of int32 * bytes 
  | NotBuffered of bytes

type packetInReason =
  | NoMatch
  | ExplicitSend
  
type packetIn =
    { input_payload : payload
    ; total_len : int16
    ; port : portId
    ; reason : packetInReason
    }

type packetOut =
    { output_payload : payload
    ; port_id : portId option
    ; apply_actions : action list
    }

type flowRemovedReason =
  | IdleTimeout
  | HardTimeout
  | Delete

type flowRemoved =
    { pattern : pattern
    ; cookie : int64
    ; priority : int16
    ; reason : flowRemovedReason
    ; duration_sec : int32
    ; duration_nsec : int32
    ; idle_timeout : timeout
    ; packet_count : int64
    ; byte_count : int64
    }

type individualStatsReq =
  { is_of_match : pattern
  ; is_table_id : int8
  ; is_out_port : pseudoPort option 
  }

type aggregateStatsReq =
  { as_of_match : pattern
  ; as_table_id : int8
  ; as_out_port : pseudoPort option
  }

type statsRequest =
  | DescriptionRequest
  | FlowTableStatsRequest
  | IndividualRequest of individualStatsReq
  | AggregateRequest of aggregateStatsReq

type descriptionStats =
    { manufacturer : string
    ; hardware : string
    ; software : string
    ; serial_number : string
    ; datapath : string
    }
 
type individualStats =
    { table_id : int8
    ; of_match : pattern
    ; duration_sec : int32 
    ; duration_nsec : int32 
    ; priority : int16
    ; idle_timeout : int16
    ; hard_timeout : int16
    ; cookie : int64
    ; packet_count : int64 
    ; byte_count : int64
    ; actions : action list 
    }

type aggregateStats =
    { total_packet_count : int64 
    ; total_byte_count : int64
    ; flow_count : int32 
    }

type statsReply =
  | DescriptionRep of descriptionStats
  | IndividualFlowRep of individualStats list
  | AggregateFlowRep of aggregateStats
  

let add_flow prio pat ?(idle_to = Permanent) ?(notify_removed = false) actions =
  { command = AddFlow;
    pattern = pat;
    priority = prio;
    actions = actions;
    cookie = 0L;
    idle_timeout = idle_to;
    hard_timeout = Permanent;
    notify_when_removed = notify_removed;
    out_port =  None;
    apply_to_packet = None;
    check_overlap = false
  }

let delete_flow_strict prio pat port =
  { command = DeleteStrictFlow
  ; pattern = pat
  ; priority = prio
  ; actions = []
  ; cookie = 0L
  ; idle_timeout = Permanent
  ; hard_timeout = Permanent
  ; notify_when_removed = false
  ; apply_to_packet = None
  ; out_port = port
  ; check_overlap = false
  }

let match_all : pattern = {
  dlSrc = None;
  dlDst = None;
  dlTyp = None;
  dlVlan = None;
  dlVlanPcp = None;
  nwSrc = None;
  nwDst = None;
  nwProto = None;
  nwTos = None;
  tpSrc = None;
  tpDst = None;
  inPort = None
}

let delete_all_flows =
  { command = DeleteFlow
  ; pattern = match_all
  ; priority = 0
  ; actions = []
  ; cookie = 0L
  ; idle_timeout = Permanent
  ; hard_timeout = Permanent
  ; notify_when_removed = false
  ; apply_to_packet = None
  ; out_port = None
  ; check_overlap = false }


let parse_payload = function
  | Buffered (_, b)
  | NotBuffered b -> 
    Packet.parse b

let marshal_payload buffer pkt =
  let payload = Packet.marshal pkt in
  match buffer with
    | Some b -> Buffered (b, payload)
    | None -> NotBuffered payload

module Format = struct

  open Format

  let bytes fmt bytes =
    try
      Packet.format_packet fmt (Packet.parse bytes)
    with exn -> (* TODO(arjun): should catch right error *)
      fprintf fmt "unparsable packet"        

  let payload fmt payload = 
    match payload with
      | NotBuffered buf -> bytes fmt buf
      | Buffered (n, buf) -> fprintf fmt "%a (buffered at %s)" bytes buf 
        (Int32.to_string n)

  let reason fmt = function
      | NoMatch -> fprintf fmt "NoMatch"
      | ExplicitSend -> fprintf fmt "ExplicitSend"

  let packetIn fmt pktIn =
    fprintf fmt 
      "@[packetIn{@;<1 2>@[@[total_len=%d@]@ @[port=%d@]@ @[reason=%a@]@ \
                    @[payload=%a@]@]@ }@]"
      pktIn.total_len pktIn.port reason pktIn.reason
      payload pktIn.input_payload

  let string_of_mk formatter x =
    let buf = Buffer.create 100 in
    let fmt = formatter_of_buffer buf in
    pp_set_margin fmt 80;
    formatter fmt x;
    fprintf fmt "@?";
    Buffer.contents buf

  let descriptionStats fmt v =
    fprintf fmt "@[{@[@[manufacturer=%s;@]@ @[hardware=%s;@]@ \
                      @[software=%s;@]@ @[serial=%s;@]@ @[datapath=%s@]@]}@]"
      v.manufacturer v.hardware v.software v.serial_number v.datapath

  (* TODO(arjun): must fill *)
  let individualStats fmt v = fprintf fmt "individualStats"

  let aggregateStats fmt v =
    fprintf fmt "@[{@[@[packets=%Ld;@]@ @[bytes=%Ld;@]@ @[flows=%ld@]@]}@]"
      v.total_packet_count v.total_byte_count v.flow_count

  let reply fmt v = match v with
    | DescriptionRep st -> descriptionStats fmt st
    | IndividualFlowRep st -> individualStats fmt st
    | AggregateFlowRep st -> aggregateStats fmt st

  let string_of_mk formatter x =
    let buf = Buffer.create 100 in
    let fmt = formatter_of_buffer buf in
    pp_set_margin fmt 80;
    formatter fmt x;
    fprintf fmt "@?";
    Buffer.contents buf

end

let packetIn_to_string  = Format.string_of_mk Format.packetIn

let reply_to_string  = Format.string_of_mk Format.reply
