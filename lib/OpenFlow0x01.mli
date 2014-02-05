open Packet
open OpenFlow0x01_Core

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
      nw_src: int;
      nw_dst: int;
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
  val move_controller_last : sequence -> sequence
  val to_string : t -> string
  val sequence_to_string : sequence -> string
  val marshal : t -> Cstruct.t -> int
  val parse : Cstruct.t -> t
  val size_of : t -> int
end

module Timeout : sig
  type t = timeout
  val to_string : t -> string
  val to_int : t -> int16
  val of_int : int16 -> t
end

module FlowMod : sig
  module Command : sig
    type t = flowModCommand
    val to_string : t -> string
    val to_int : t -> int16
    val of_int : int16 -> t
  end
  type t = flowMod
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
  val to_string : t -> string
end

module PortDescription : sig

  module PortConfig : sig
    type t = portConfig
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
    val to_string : t -> string
    val of_int : Int32.t -> t
    val to_int : t -> Int32.t
  end

  module PortFeatures : sig
    type t = portFeatures
    val to_string : t -> string
    val of_int : Int32.t -> t
    val to_int : t -> Int32.t
  end
  type t = portDescription
  val to_string : t -> string
  val parse : Cstruct.t -> t
  val marshal : t -> Cstruct.t -> int
  val size_of : t -> int
end

module PortStatus : sig
  module ChangeReason : sig
    type t = portChangeReason
    val to_string : t -> string
  end
  type t = portStatus
  val to_string : t -> string
  val parse : Cstruct.t -> t
  val marshal : t -> Cstruct.t -> int
  val size_of : t -> int
end

module SwitchFeatures : sig
  type supported_wildcards = supportedWildcards
  module Capabilities : sig
    type t = capabilities
    val to_string : t -> string
  end
  module SupportedActions : sig
    type t = supportedActions
    val to_string : t -> string
  end
  type t = switchFeatures
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

module Error : sig

  module HelloFailed : sig
    type t = helloFailed
    val to_string : t -> string
  end

  module BadRequest : sig
    type t = badRequest
    val to_string : t -> string

  end

  module BadAction : sig
    type t = badAction
    val to_string : t -> string
  end

  module FlowModFailed : sig
    type t = flowModFailed
    val to_string : t -> string
  end

  module PortModFailed : sig
    type t = portModFailed
    val to_string : t -> string
  end

  module QueueOpFailed : sig
    type t = queueOpFailed
    val to_string : t -> string
  end

  type c = errorCode
  type t = error
  val to_string : t -> string

end

module Vendor : sig
  type t = int32 * Cstruct.t  
  val parse : Cstruct.t -> t
  val marshal : t -> Cstruct.t  -> int  
end

module Message : sig
  type t = message
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

val string_of_switchId : switchId -> string
val string_of_portId : portId -> string
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
