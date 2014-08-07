open Packet
open OpenFlow0x05_Core

type msg_code =  | HELLO | ERROR | ECHO_REQ | ECHO_RESP | EXPERIMENTER | FEATURES_REQ
                 | FEATURES_RESP | GET_CONFIG_REQ | GET_CONFIG_RESP 
                 | SET_CONFIG | PACKET_IN | FLOW_REMOVED | PORT_STATUS | PACKET_OUT
                 | FLOW_MOD | GROUP_MOD | PORT_MOD | TABLE_MOD | MULTIPART_REQ
                 | MULTIPART_RESP | BARRIER_REQ | BARRIER_RESP | ROLE_REQ 
                 | ROLE_RESP | GET_ASYNC_REQ | GET_ASYNC_REP | SET_ASYNC 
                 | METER_MOD | ROLE_STATUS | TABLE_STATUS | REQUEST_FORWARD 
                 | BUNDLE_CONTROL | BUNDLE_ADD_MESSAGE

module PortDesc : sig

  module Config : sig

    type t = portConfig

    val marshal : t -> int32

    val parse : int32 -> t

    val to_string : t -> string

  end

  module State : sig

    type t = portState

    val marshal : t -> int32

    val parse : int32 -> t

    val to_string : t -> string

  end

  module Properties : sig

    module EthFeatures : sig

      type t = ethFeatures

      val to_string : t -> string

      val marshal : t -> int32

      val parse : int32 -> t    

    end

    module OptFeatures : sig

      type t = opticalFeatures

      val to_string : t -> string

      val marshal : t -> int32

      val parse : int32 -> t    

   end

   type t = portProp

   val sizeof : t -> int

   val to_string : t -> string

   val marshal : Cstruct.t -> t -> int

   val parse : Cstruct.t -> t

  end

  type t = portDesc

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module Oxm : sig

  type t = oxm

  val field_name : t -> string

  val sizeof : t -> int 

  val sizeof_headers : t list -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val marshal_header : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t * Cstruct.t

  val parse_header : Cstruct.t -> t * Cstruct.t

end

module OfpMatch : sig

  type t = oxmMatch

  val sizeof : t -> int

  val to_string : t -> string 

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t * Cstruct.t

end

module PseudoPort : sig

  type t = OpenFlow0x04_Core.pseudoPort

  val size_of : t -> int

  val to_string : t -> string

  val marshal : t -> int32

  val make : int32 -> int16 -> t

end

module Action : sig

  type sequence = OpenFlow0x04_Core.actionSequence

  type t = OpenFlow0x04_Core.action

  val sizeof : t -> int

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val parse_sequence : Cstruct.t -> sequence

  val to_string :  t -> string
    
end

module Instruction : sig

  type t = OpenFlow0x04_Core.instruction

  val to_string : t -> string

  val sizeof : t -> int

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t ->  t

end

module Instructions : sig

  type t = OpenFlow0x04_Core.instruction list

  val sizeof : t -> int

  val marshal : Cstruct.t -> t -> int

  val to_string : t -> string

  val parse : Cstruct.t -> t

end

module Experimenter : sig

  type t = experimenter

  val sizeof : t -> int

  val marshal : Cstruct.t -> t -> int

  val to_string : t -> string

  val parse : Cstruct.t -> t

end

module SwitchFeatures : sig

  type t = OpenFlow0x04.SwitchFeatures.t

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module SwitchConfig : sig

  type t = OpenFlow0x04_Core.switchConfig

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module TableMod : sig

  module Properties : sig

    type t = tableProperties

    val sizeof : t -> int

    val to_string : t -> string

    val marshal : Cstruct.t -> t -> int

    val parse : Cstruct.t -> t

  end

  type t = tableMod

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module FlowMod : sig

  module FlowModCommand : sig
      
    type t = flowModCommand

    val sizeof : t -> int

    val marshal : t -> int

    val parse : int -> t

    val to_string : t -> string

  end

  type t = flowMod

  val sizeof : t -> int

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val to_string : t -> string

end

module Bucket : sig

  type t = OpenFlow0x04_Core.bucket

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t  
end

module GroupMod : sig

  type t = OpenFlow0x04_Core.groupMod

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module PortMod : sig

  type t = portMod

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module Message : sig

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

  val sizeof : t -> int

  val to_string : t -> string

  val blit_message : t -> Cstruct.t -> int
  
  val header_of : xid -> t -> OpenFlow_Header.t

  val marshal : xid -> t -> string

  val parse : OpenFlow_Header.t -> string -> (xid * t)
  
  val marshal_body : t -> Cstruct.t -> unit
   
end
