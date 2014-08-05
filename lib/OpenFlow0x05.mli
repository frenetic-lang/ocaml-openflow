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

module Message : sig

  type t =
    | Hello

  val sizeof : t -> int

  val to_string : t -> string

  val blit_message : t -> Cstruct.t -> int
  
  val header_of : xid -> t -> OpenFlow_Header.t

  val marshal : xid -> t -> string

  val parse : OpenFlow_Header.t -> string -> (xid * t)
  
  val marshal_body : t -> Cstruct.t -> unit
   
end
