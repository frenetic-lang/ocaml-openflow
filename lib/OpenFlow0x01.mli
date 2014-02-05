open Packet
open OpenFlow0x01_Core

type switchId = OpenFlow0x01_Core.switchId

type portId = OpenFlow0x01_Core.portId

type queueId = OpenFlow0x01_Core.queueId

type xid = OpenFlow0x01_Core.xid

module Wildcards : sig

    type t = {
      in_port: bool;
      dl_vlan: bool;
      dl_src: bool;
      dl_dst: bool;
      dl_type: bool;
      nw_proto: bool;
      tp_src: bool;
      tp_dst: bool;
      nw_src: int; (* XXX: unsigned *)
      nw_dst: int; (* XXX: unsigned *)
      dl_vlan_pcp: bool;
      nw_tos: bool;
    }

    val to_string : t -> string

    val marshal : t -> int32
    val parse : int32 -> t

end

module Match : sig

  type t = pattern

  val to_string : t -> string

  val marshal : t -> Cstruct.t -> int
  val parse : Cstruct.t -> t

  val size_of : t -> int

end

module PseudoPort : sig

  type t = pseudoPort

  val to_string : t -> string

  val marshal : t -> int
  val make : int -> int -> t

end

module Action : sig

  type t = action

  type sequence = t list

  (** [move_controller_last seq] produces a semantically-equivalent list of
  actions with actions that send packets to the controller moved to the end.
  This works around a known bug in the OpenFlow reference switch where actions
  in an action sequence after a "send to controller" ([Output (Controller n)])
  action are ignored. *)
  val move_controller_last : sequence -> sequence

  (** [to_string v] pretty-prints [v]. *)
  val to_string : t -> string

  (** [sequence_to_string v] pretty-prints an action sequence. *)
  val sequence_to_string : sequence -> string

  val marshal : t -> Cstruct.t -> int
  val parse : Cstruct.t -> t

  val size_of : t -> int

end

(** The type of flow rule timeouts.  See Section 5.3.3 of the OpenFlow 1.0
specification. *)
module Timeout : sig

  type t = timeout

  (** [to_string v] pretty-prints [v]. *)
  val to_string : t -> string

  val to_int : t -> int16
  val of_int : int16 -> t
end

(** A flow modification data structure.  See Section 5.3.3 of the OpenFlow 1.0
specification. *)
module FlowMod : sig

  (** See the [ofp_flow_mod_command] enumeration in Section 5.3.3 of the 
  OpenFlow 1.0 specification. *)
  module Command : sig

    type t = flowModCommand

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

    val to_int : t -> int16
    val of_int : int16 -> t

  end

  type t = flowMod


  (** [to_string v] pretty-prints [v]. *)
  val to_string : t -> string

  val marshal : t -> Cstruct.t -> int
  val parse : Cstruct.t -> t

  val size_of : t -> int

end


module Payload : sig

  type t = payload

end

module PacketIn : sig

  module Reason : sig

    type t = packetInReason

  end

  type t = packetIn

end

(** Flow removed data structure. See section 5.4.3 of the OpenFlow 1.0 specification. *)
module FlowRemoved : sig

  module Reason : sig

    type t = flowRemovedReason

    val to_string : t -> string

    val to_int : t -> int16
    val of_int : int16 -> t

  end

  type t = flowRemoved

  val to_string : t -> string

  val marshal : t -> Cstruct.t -> int
  val parse : Cstruct.t -> t

  val size_of : t -> int

end

module PacketOut : sig

  type t = packetOut

  (** [to_string v] pretty-prints [v]. *)
  val to_string : t -> string

end

module PortDescription : sig

  module PortConfig : sig

    type t = portConfig

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string


    val to_int : t -> Int32.t
    val of_int : Int32.t -> t
  end

  module PortState : sig

    module StpState : sig
      type t = stpState

      val of_int : Int32.t -> t
      val to_int : t -> Int32.t

      val to_string : t -> string
    end

    type t = portState

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

    val of_int : Int32.t -> t
    val to_int : t -> Int32.t

  end

  (** See the [ofp_port_features] enumeration in Section 5.2.1 of the OpenFlow
  1.0 specification. *)
  module PortFeatures : sig

    type t = portFeatures

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

    val of_int : Int32.t -> t
    val to_int : t -> Int32.t

  end

  type t = portDescription

  (** [to_string v] pretty-prints [v]. *)
  val to_string : t -> string

  val parse : Cstruct.t -> t
  val marshal : t -> Cstruct.t -> int

  val size_of : t -> int

end

(** Port status message.  See Section 5.4.3 of the OpenFlow 1.0 specification. *)
module PortStatus : sig

  module ChangeReason : sig

    type t = portChangeReason
    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

  end

  type t = portStatus

  (** [to_string v] pretty-prints [v]. *)
  val to_string : t -> string

  val parse : Cstruct.t -> t
  val marshal : t -> Cstruct.t -> int

  val size_of : t -> int

end

(** Switch features data structure.  See Section 5.3.1 of the OpenFlow 1.0
specification. *)
module SwitchFeatures : sig

  (** Fields that support wildcard patterns on this switch. *)
  type supported_wildcards = supportedWildcards

  (** See the [ofp_capabilities] enumeration in Section 5.3.1 of the OpenFlow
  1.0 specification. *)
  module Capabilities : sig


    type t = capabilities

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

  end

  (** Describes which actions ([Action.t]) this switch supports. *)
  module SupportedActions : sig

    type t = supportedActions
    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

  end

  type t = switchFeatures

  (** [to_string v] pretty-prints [v]. *)
  val to_string : t -> string

end

module ConfigReply : sig
    
  module FragFlags : sig

    type t = fragFlags

    val to_string : t -> string
  end
    
  type t = switchConfig
      
  val to_string : t -> string 
end


module SwitchConfig : sig
    
  module FragFlags : sig

    type t = fragFlags

    val to_string : t -> string
  end
    
  type t = switchConfig
      
  val to_string : t -> string 
end

module StatsRequest : sig
  type t = statsRequest
  val to_string : t -> string
end

module StatsReply : sig

  type t = statsReply
  
  val parse : Cstruct.t -> t
  
  val marshal : t -> Cstruct.t -> int
  
end

(** An error message.  See Section 5.4.4 of the OpenFlow 1.0 specification. *)
module Error : sig

  module HelloFailed : sig

    type t =
      | Incompatible (** No compatible version. *)
      | Eperm (** Permissions error. *)

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

  end

  module BadRequest : sig

    type t =
      | BadVersion (** [Header] version not supported. *)
      | BadType (** [Message] type not supported. *)
      | BadStat (** StatsRequest type not supported. *)
      | BadVendor (** Vendor not supported. *)
      | BadSubType (** Vendor subtype not supported. *)
      | Eperm (** Permissions error. *)
      | BadLen (** Wrong request length for type. *)
      | BufferEmpty (** Specified buffer has already been used. *)
      | BufferUnknown (** Specified buffer does not exist. *)

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

  end

  module BadAction : sig

    type t =
      | BadType (** Unknown action type. *)
      | BadLen (** Length problem in actions. *)
      | BadVendor (** Unknown vendor id specified. *)
      | BadVendorType (** Unknown action type for vendor id. *)
      | BadOutPort (** Problem validating output action. *)
      | BadArgument (** Bad action argument. *)
      | Eperm (** Permissions error. *)
      | TooMany (** Can't handle this many actions. *)
      | BadQueue (** Problem validating output queue. *)

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

  end

  module FlowModFailed : sig

    type t =
      | AllTablesFull (** Flow not added because of full tables. *)
      | Overlap (** Attepted to add overlapping flow with 
                [FlowMod.check_overlap] set. *)
      | Eperm (** Permissions error. *)
      | BadEmergTimeout (** Flow not added because of non-zero idle/hard timeout. *)
      | BadCommand (** Unknown command. *)
      | Unsupported (** Unsupported action list - cannot process in the order
                    specified. *)

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

  end

  module PortModFailed : sig

    type t =
      | BadPort (** Specified port does not exist. *)
      | BadHwAddr (** Specified hardware address is wrong. *)

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

  end

  module QueueOpFailed : sig

    type t =
      | BadPort (** Invalid port (or port does not exist). *)
      | BadQueue (** Queue does not exist. *)
      | Eperm (** Permissions error. *)

    (** [to_string v] pretty-prints [v]. *)
    val to_string : t -> string

  end

  


  (** Each error is composed of a pair (error_code, data) *)
  type c =
  
    (** Hello protocol failed. *)
    | HelloFailed of HelloFailed.t

    (** Request was not understood. *)
    | BadRequest of BadRequest.t

    (** Error in action description *)
    | BadAction of BadAction.t

    (** Problem modifying flow entry. *)
    | FlowModFailed of FlowModFailed.t

    (** Port mod request failed. *)
    | PortModFailed of PortModFailed.t

    (** Queue operation failed. *)
    | QueueOpFailed of QueueOpFailed.t
  
  type t = 
  
    | Error of c * Cstruct.t

  (** [to_string v] pretty-prints [v]. *)
  val to_string : t -> string

end

(** A VENDOR message.  See Section 5.5.4 of the OpenFlow 1.0 specification. *)
module Vendor : sig

  type t = int32 * Cstruct.t
  
  val parse : Cstruct.t -> t

  val marshal : t -> Cstruct.t  -> int
  
end

(** A subset of the OpenFlow 1.0 messages defined in Section 5.1 of the 
specification. *)
module Message : sig

  type t =
    | Hello of bytes
    | ErrorMsg of Error.t
    | EchoRequest of bytes
    | EchoReply of bytes
    | VendorMsg of int32 * Cstruct.t
    | SwitchFeaturesRequest
    | SwitchFeaturesReply of switchFeatures
    | FlowModMsg of flowMod
    | PacketInMsg of packetIn
    | FlowRemovedMsg of flowRemoved
    | PortStatusMsg of portStatus
    | PacketOutMsg of packetOut
    | BarrierRequest
    | BarrierReply
    | StatsRequestMsg of statsRequest
    | StatsReplyMsg of statsReply
    | SetConfig of switchConfig
    | ConfigRequestMsg
    | ConfigReplyMsg of switchConfig

  (** [size_of msg] returns the size of [msg] in bytes when serialized. *)
  val size_of : t -> int

  val header_of : xid -> t -> OpenFlow_Header.t

  (** [parse hdr bits] parses the body of a message with header [hdr] from
      buffer [bits]. 
      @param hdr Header of the message to be parsed from [bits].
      @param bits string containing a serialized message body.
      @return [(xid, message)] where [xid] is the transaction ID.
      @raise Unparsable if [bits] cannot be parsed.
      @raise Ignored if [bits] contains a valid OpenFlow message that the 
             parser does not yet handle. *)
  val parse : OpenFlow_Header.t -> string -> (xid * t)

  val marshal_body : t -> Cstruct.t -> unit
  
  (** [marshal xid msg] serializes [msg], giving it a transaction ID [xid]. *)
  val marshal : xid -> t -> string

  (** [to_string msg] pretty-prints [msg]. *)
  val to_string : t -> string

end


(** {9 Pretty printing}

    In general, each submodule contains pretty-printing functions for the types
    defined therein.  This section defines pretty printers for top-level types.
*)

(** [string_of_switchId sw] pretty-prints [sw] in hex. *)
val string_of_switchId : switchId -> string

(** [string_of_portId p] pretty-prints [p]. *)
val string_of_portId : portId -> string

(** [string_of_queueId q] pretty-prints [q]. *)
val string_of_queueId : queueId -> string

(** {9 Parsing exceptions}

    These exceptions may occur when parsing OpenFlow messages.
*)

(** [Unparsable msg] signals an error in parsing, such as when a bit sequence
has been corrupted. *)
exception Unparsable of string

(** [Ignored msg] signals the arrival of a valid OpenFlow message that the
parser is not yet equipped to handle. *)
exception Ignored of string
