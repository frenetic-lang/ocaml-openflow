open Packet

type 'a mask = { m_value : 'a; m_mask : 'a option }

type switchId = int64

type portId = int16

type queueId = int32

type xid = OpenFlow_Header.xid

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

type request =
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

type reply =
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

let match_all = {
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
