(** Library for constructing, marshalling, and parsing OpenFlow 1.0 messages.
It is largely drawn from the OpenFlow 1.0 specification:

{{:http://www.openflow.org/documents/openflow-spec-v1.0.0.pdf}
http://www.openflow.org/documents/openflow-spec-v1.0.0.pdf}

Most data structures are documented with a pointer to relevent section in the
OpenFlow 1.0 specification, rather than reproducing the specification here. *)

open Packet

(** [switchId] is the type of switch identifiers received as part of
[SwitchFeature] replies. *)
type switchId = int64

(** [portId] is the type of physical port identifiers (port numbers). *)
type portId = int16

(** [queueId] identifies a specific queue for QoS. *)
type queueId = int32


(** {2 Configuration} *)


(** See the [ofp_port_config] enumeration in Section 5.2.1 of the OpenFlow 
1.0 specification. *)
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

(** See the [ofp_port_state] enumeration in Section 5.2.1 of the OpenFlow 
  1.0 specification.
  
  The [stp_X] fields have no effect on switch operation.  The controller must
  adjust [PortConfig.no_recv], [PortConfig.no_fwd], and
  [PortConfig.no_packet_in] to fully implement an 802.1D tree. *)
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

(** See the [ofp_port_reason] enumeration in Section 5.4.3 of the OpenFlow
1.0 specification. *)
type portChangeReason =
  | Add (** The port was added. *)
  | Delete (** The port was removed. *)
  | Modify (** Some attribute of the port has changed. *)

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

(** {2 OpenFlow types}

    These types are primarily drawn from Section 5 of the OpenFlow 1.0
    specification.
*)

type 'a mask = { m_value : 'a; m_mask : 'a option }

(** Transaction ID of OpenFlow messages. *)
type xid = OpenFlow_Header.xid

(** A pattern that matches a packet headers.

    For each field, write [Some x] indicates that the headers must be
    [x], where [None] is a wildcard. *)
type pattern =  
    { dlSrc : dlAddr option (** Ethernet source address. *)
    ; dlDst : dlAddr option (** Etherent destination address. *)
    ; dlTyp : dlTyp option (** Ethernet frame type. *)
    ; dlVlan : dlVlan option (** Input VLAN id. *)
    ; dlVlanPcp : dlVlanPcp option (** Input VLAN priority. *)
    ; nwSrc : nwAddr mask option (** IP source address. *)
    ; nwDst : nwAddr mask option (** IP destination address. *)
    ; nwProto : nwProto option (** IP protocol. *)
    ; nwTos : nwTos option (** IP ToS. *)
    ; tpSrc : tpPort option (** TCP/UDP source port. *)
    ; tpDst : tpPort option (** TCP/UDP destination port. *)
    ; inPort : portId option (** Input switch port. *)
    }

(** A pseudo-port, as described by the [ofp_port] enumeration in
    Section 5.2.1 of the OpenFlow 1.0 specification. *)
type pseudoPort =
  | PhysicalPort of portId
  | AllPorts (** All physical ports except input port. *)

  | InPort (** Send the packet out the input port.  This virtual port
               must be explicitly used in order to send back out of
               the input port. *)
  | Flood (** All physical ports except input port and those disabled by 
              STP. *)
  | Controller of int (** Send to controller along with [n] (max 1024)
                          bytes of the packet. *)

(** Flow action data structure.  See Section 5.2.4 of the OpenFlow 1.0
    specification. *)
type action =
  | Output of pseudoPort (** Output to switch port. *)
  | SetDlVlan of dlVlan (** Set the 802.1Q VLAN ID.  A value of None strips 
                        the 802.1Q header. *)
  | SetDlVlanPcp of dlVlanPcp (** Set the 802.1Q priority. *)
  | SetDlSrc of dlAddr (** Set ethernet source address. *)
  | SetDlDst of dlAddr (** Set ethernet destination address. *)
  | SetNwSrc of nwAddr (** Set IP source address. *)
  | SetNwDst of nwAddr (** Set IP destination address. *)
  | SetNwTos of nwTos (** Set IP ToS. *)
  | SetTpSrc of tpPort (** Set TCP/UDP source port. *)
  | SetTpDst of tpPort (** Set TCP/UDP destination port. *)
  | Enqueue of pseudoPort * queueId (** Enqueue to a switch queue *)

(** The type of flow rule timeouts.  See Section 5.3.3 of the OpenFlow 1.0
    specification. *)
type timeout =
  | Permanent (** No timeout. *)
  | ExpiresAfter of int16 (** Time out after [n] seconds. *)

(** See the [ofp_flow_mod_command] enumeration in Section 5.3.3 of the 
    OpenFlow 1.0 specification. *)
type flowModCommand =
  | AddFlow (** New flow. *)
  | ModFlow (** Modify all matching flows. *)
  | ModStrictFlow (** Modify entry strictly matching wildcards. *)
  | DeleteFlow (** Delete all matching flows. *)
  | DeleteStrictFlow (** Delete entry strictly matching wildcards. *)

(** A flow modification data structure.  See Section 5.3.3 of the OpenFlow 1.0
specification. *)
type flowMod =
    { command : flowModCommand
    ; pattern: pattern (** Fields to match. *)
    ; priority : int16 (** Priority level of flow entry. *)
    ; actions : action list (** Actions. *)
    ; cookie : int64 (** Opaque controller-issued identifier. *)
    ; idle_timeout : timeout (** Idle time before discarding (seconds). *)
    ; hard_timeout : timeout (** Max time before discarding (seconds). *)
    ; notify_when_removed : bool (** Send flow removed message when flow
                                 expires or is deleted. *)
    ; apply_to_packet : int32 option (** Optional buffered packet to apply 
                                     to. *)
    ; out_port : pseudoPort option (** For [DeleteFlow] and 
                                     [DeleteStrictFlow] modifications, require
                                     matching entries to include this as an
                                     output port.  A value of [None] indicates
                                     no restriction. *)
    ; check_overlap : bool (** Check for overlapping entries first. *)
    }

(** The payload for [packetIn] and [packetOut] messages. *)
type payload =
  | Buffered of int32 * bytes 
    (** [Buffered (id, buf)] is a packet buffered on a switch. *)
  | NotBuffered of bytes

type packetInReason =
  | NoMatch
  | ExplicitSend

(** A packet-in message.  See Section 5.4.1 of the OpenFlow 1.0
    specification. *)
type packetIn =
    { input_payload : payload 
    (** The packet contents, which may truncated, in which case, 
        the full packet is buffered on the switch. *)
    ; total_len : int16
      (** The length of the full packet, which may exceed the length
          of [payload] if the packet is buffered. *)
    ; port : portId (** Port on which frame was received. *)
    ; reason : packetInReason (** Reason packet is being sent. *)
    }

type flowRemovedReason =
  | IdleTimeout
  | HardTimeout
  | Delete

(** A flow-removed message.  See Section 5.4.2 of the OpenFlow 1.0
    specification. *)
type flowRemoved =
    { pattern : pattern;
      cookie : int64;
      priority : int16;
      reason : flowRemovedReason;
      duration_sec : int32;
      duration_nsec : int32;
      idle_timeout : timeout;
      packet_count : int64;
      byte_count : int64
    }

(** A send-packet message.  See Section 5.3.6 of the OpenFlow 1.0
    specification. *)
type packetOut =
    { output_payload : payload
    ; port_id : portId option (** Packet's input port. *)
    ; apply_actions : action list (** Actions. *)
    }

(** Both [IndividualRequest] and [AggregateRequest] take as paramters,
    a [pattern] that specifies the fields to match, the [table_id]
    to read from, and an optional port, which requires matching
    entries to have this as an output port.  Use table ID [0xFF] to
    read from all tables. *)

(** The body of an individual flow stat request. *)
type individualStatsReq =
  { is_of_match : pattern
  ; is_table_id : int8
  ; is_out_port : pseudoPort option
  }

(** The body of an aggregate flow stat request. *)
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

  (** The body of a reply to a description request. *)
type descriptionStats =
    { manufacturer : string (** Manufacturer description. *)
    ; hardware : string (** Hardware description. *)
    ; software : string (** Software description. *)
    ; serial_number : string (** Serial number. *)
    ; datapath : string (** Human readable description of datapath. *)
    }
      
  (** The body of a reply to an individual flow statistics request. *)
type individualStats =
    { table_id : int8 (** ID of table flow came from. *)
    ; of_match : pattern (** Description of fields. *)
    ; duration_sec : int32 (** Time flow has been alive in seconds. *)
    ; duration_nsec : int32 (** Time flow has been alive in nanoseconds 
                                beyond [duration_sec]. *)
    ; priority : int16 (** Priority of the entry.  Only meaningful when this
                           is not an exact-match entry. *)
    ; idle_timeout : int16 (** Number of seconds idle before expiration. *)
    ; hard_timeout : int16 (** Number of seconds before expiration. *)
    ; cookie : int64 (** Opaque controller-issued identifier. *)
    ; packet_count : int64 (** Number of packets in flow. *)
    ; byte_count : int64 (** Number of bytes in flow. *)
    ; actions : action list (** Actions. *)
    }

type aggregateStats =
    { total_packet_count : int64 (** Number of packets in flows. *)
    ; total_byte_count : int64 (** Number of bytes in flows. *)
    ; flow_count : int32 (** Number of flows. *)
    }

(** A statistics reply message.  See Section 5.3.5 of the OpenFlow 1.0 
      specification. *)
type statsReply =
  | DescriptionRep of descriptionStats
  | IndividualFlowRep of individualStats list
  | AggregateFlowRep of aggregateStats

(** {2 Convenient Functions} *)

val parse_payload : payload -> Packet.packet

(** [marshal_payload buf pkt] serializes pkt, where [buf] is an optional 
buffer ID. *)
val marshal_payload : int32 option -> Packet.packet -> payload

(** A pattern that matches all packets. (All fields wildcarded.) *)
val match_all : pattern

(** [add_flow priority pattern action_sequence] creates a
    [FlowMod.t] instruction that adds a new flow table entry with
    the specified [priority], [pattern], and [action_sequence].

    The entry is permanent (i.e., does not timeout), its cookie is
    zero, etc. *)
val add_flow : int16 -> pattern -> ?idle_to:timeout -> ?notify_removed:bool -> action list -> flowMod

val delete_flow_strict : int16 -> pattern -> pseudoPort option -> flowMod

val delete_all_flows : flowMod

(** {2 Printing and Debugging} *)

val packetIn_to_string : packetIn -> string

(** {3:patternexamples Pattern Examples}

    For example, the following pattern matches all packets from the
    host with Ethernet address 00:00:00:00:00:12:
    
[
let from_host12 = {
  dlSrc = Some 0x000000000012L;
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
]

    This is quite verbose. You can abbreviate using functional update.
    The builtin pattern {! match_all} has all fields sets to
    [None]. So, the following definition is identical to the one
    above:

    [let from_host12 = { match_all with dlSrc = Some 0x000000000012L }]

    Here are a few more examples.

    This pattern matches all packets:
    
    [let all_ip = { match_all with dlTyp = Some 0x800 }]

    This pattern matches all packets with source IP address 10.0.0.1:
    
    [let from_10_0_0_1 = { match_all with dlTyp = Some 0x800; nwSrc = Some 0x10000001 }]

    This pattern matches all TCP packets:
    [let al_tcp = { match_all with dlTyp = Some 0x800; nwProto = Some 6 }]

    Note that to match IP-level headers, e.g., [nwProto] and [nwSrc]),
    we have to write [dlTyp = Some 0x800], or they are ignored.
*)



val reply_to_string : statsReply -> string
