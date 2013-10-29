(** A uniform interface to OpenFlow 1.0 and 1.3.

  A high-level language, such as Frenetic, should support OpenFlow 1.0
  and also exploit OpenFlow 1.3 features when possible. For example,
  when two Frenetic actions are composed in parallel, they logically work
  on two copies of a packet. Certain kinds of parallel composition cannot
  be realized in OpenFlow 1.0, but they are trivial to implement with
  group tables in OpenFlow 1.3.

  Similarly, OpenFlow 1.3 can implement failover efficiently using fast-
  failover groups. But, in OpenFlow 1.0, we have to incur a round-trip
  to the controller.

  Instead of creating two different versions of the Frenetic compiler, we
  here define a high-level action data type. When targeting OpenFlow 1.0,
  actions translates to 1.0 action sequences and controller round-trips
  if needed. When targeting OpenFlow 1.3, action also builds group
  tables to realize actions efficiently. This requires a global analysis
  of all the actions in a flow table. Therefore, Frenetic needs to
  supply the entire flow table at once and cannot add and remove flow table
  entries individually. *)

(** {1 OpenFlow Identifier Types}

  OpenFlow requires identifiers for switches, ports, transaction numbers, etc.
  The representation of these identifiers varies across different versions
  of OpenFlow, which is why they are abstract.


*)

type int8 = int
type int12 = int
type int16 = int
type int32 = Int32.t
type int64 = Int64.t
type int48 = Int64.t
type bytes = string

type switchId = VInt.t

type bufferId =
  | OF10BufferId of int32
  | OF13BufferId of OpenFlow0x04_Core.bufferId

exception Unsupported of string

(** {1 Packet Forwarding} *)

type port =
  | PhysicalPort of VInt.t
  | AllPorts
  | Controller of int

type field =
  | InPort
  | EthType
  | EthSrc
  | EthDst
  | Vlan
  | VlanPcp
  | IPProto
  | IP4Src
  | IP4Dst
  | TCPSrcPort
  | TCPDstPort

type fieldVal = VInt.t

module FieldMap : Map.S
  with type key = field

(** WARNING: There are dependencies between different fields that must be met. *)
type pattern = fieldVal FieldMap.t

type action =
  | OutputAllPorts
  | OutputPort of VInt.t
  | SetField of field * fieldVal

type seq = action list

type par = seq list

type group = par list

type timeout =
  | Permanent (** No timeout. *)
  | ExpiresAfter of int16 (** Time out after [n] seconds. *)

type flow = {
  pattern: pattern;
  action: group;
  cookie: int64;
  idle_timeout: timeout;
  hard_timeout: timeout
}

(** Priorities are implicit *)
type flowTable = flow list 

(** {1 Controller Packet Processing} *)

(** The payload for [packetIn] and [packetOut] messages. *)
type payload =
  | Buffered of bufferId * bytes 
    (** [Buffered (id, buf)] is a packet buffered on a switch. *)
  | NotBuffered of bytes

type packetInReason =
  | NoMatch
  | ExplicitSend

(** [(payload, total_length, in_port, reason)] *)
type pktIn = payload * int * VInt.t * packetInReason

(* {1 Switch Configuration} *)

(** A simplification of the _switch features_ message from OpenFlow *)
type switchFeatures = {
  switch_id : switchId;
  switch_ports : VInt.t list
}

(* {1 Statistics} *)

(** The body of a reply to an individual flow statistics request. *)
type flowStats = {
  flow_table_id : int8; (** ID of table flow came from. *)
  flow_pattern : pattern;
  flow_duration_sec: int32;
  flow_duration_nsec: int32;
  flow_priority: int16;
  flow_idle_timeout: int16;
  flow_hard_timeout: int16;
  flow_action: action;
  flow_packet_count: int64;
  flow_byte_count: int64
}

(* {1 Errors} *)

(* TODO: FILL *)

(* {1 Pretty-printing } *)

val format_action : Format.formatter -> action -> unit
val format_seq : Format.formatter -> seq -> unit
val format_par : Format.formatter -> par -> unit
val format_group : Format.formatter -> group -> unit
val format_field : Format.formatter -> field -> unit
val format_flow : Format.formatter -> flow -> unit
val format_flowTable : Format.formatter -> flowTable -> unit

val string_of_flowTable : flowTable -> string
val string_of_flow : flow -> string
val string_of_par : par -> string

module type SWITCH = sig

  type t
  (** [setup_flow_table sw tbl] returns after [sw] is configured to implement 
      [tbl]. [setup_flow_table] fails if [sw] runs a version of OpenFlow that
      does not support the features that [tbl] requires. *)
  val setup_flow_table : t -> flowTable -> unit Lwt.t
  val flow_stats_request : t -> pattern -> flowStats list Lwt.t
  val packet_in : t -> pktIn Lwt_stream.t
  val packet_out : t -> payload -> par -> unit Lwt.t
  val disconnect : t -> unit Lwt.t
  val features : t -> switchFeatures
end
