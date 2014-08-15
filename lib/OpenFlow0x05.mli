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

module Capabilities : sig

  type t = capabilities

  val to_int32 : t -> int32

  val to_string : t -> string

  val parse : int32 -> t

end



module SwitchFeatures : sig

  type t = switchFeatures

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

  module Properties : sig

    type t = portModPropt

    val sizeof : t -> int

    val to_string : t -> string

    val marshal : Cstruct.t -> t -> int

    val parse : Cstruct.t -> t
  
  end

  type t = portMod

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module MeterMod : sig

  type t = OpenFlow0x04_Core.meterMod

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module FlowRemoved : sig

  type t = flowRemoved

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end


module FlowRequest : sig

  type t = flowRequest

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module QueueRequest : sig

  type t = queueRequest
    
  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val sizeof : t -> int

  val to_string : t -> string

end

module TableFeature : sig

  type t = tableFeatures

  val sizeof : t -> int

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val to_string : t -> string

end

module QueueDescReq : sig

  type t = queueDescRequest

  val sizeof : t -> int

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val to_string : t -> string

end

module FlowMonitorRequest : sig

  type t = flowMonitorReq

  val sizeof : t -> int

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val to_string : t -> string

end

module MultipartReq : sig

  type t = multipartRequest

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int
 
  val parse : Cstruct.t -> t

end

module GroupStats : sig
  
  type t = groupStats

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t ->  t -> int

  val parse : Cstruct.t ->  t

  val length_func : Cstruct.t -> int option

end

module SwitchDescriptionReply : sig

  type t = switchDesc

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end


module FlowStats : sig

  type t = flowStats

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val length_func : Cstruct.t -> int option

end


module AggregateStats : sig

  type t = aggregStats

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module TableStats : sig

  type t = tableStats

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val length_func : Cstruct.t -> int option

end

module PortStats : sig

  module Properties : sig

    type t = portStatsProp

    val sizeof : t -> int

    val to_string : t -> string

    val marshal : Cstruct.t -> t -> int

    val parse : Cstruct.t -> t

    val length_func : Cstruct.t -> int option

  end
 
  type t = portStats

  val sizeof : t-> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module QueueStats : sig

  module Properties : sig

    type t = queueStatsProp

    val sizeof : t -> int

    val to_string : t -> string

    val marshal : Cstruct.t -> t -> int

    val parse : Cstruct.t -> t

    val length_func : Cstruct.t -> int option

  end

  type t = queueStats

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t 

end

module GroupDesc : sig

  type t = groupDesc

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val length_func : Cstruct.t -> int option

end

module GroupFeatures : sig

  type t = groupFeatures

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t 

end

module MeterStats : sig

  type t = meterStats

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val length_func : Cstruct.t -> int option

end

module MeterConfig : sig

  type t = meterConfig

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val length_func : Cstruct.t -> int option

end


module MeterFeatures : sig

  type t = meterFeatures

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module FlowMonitorReply : sig

  type t = flowMonitorReply

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val length_func : Cstruct.t -> int option

end

module TableDescReply : sig

  type t = tableDescReply

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val length_func : Cstruct.t -> int option

end

module QueueDescReply : sig

  module Properties : sig

    type t = queueDescProp

    val sizeof : t -> int

    val to_string : t -> string

    val marshal : Cstruct.t -> t -> int

    val parse : Cstruct.t -> t

    val length_func : Cstruct.t -> int option

  end

  type t = queueDescReply

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val length_func : Cstruct.t -> int option

end

module MultipartReply : sig

  type t = multipartReply

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end  

module PacketOut : sig

  type t = packetOut

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module RoleRequest : sig

  module Role : sig

    type t = controllerRole

    val to_string : t -> string

    val marshal : t -> int32

    val parse : int32 -> t
  end  

  type t = roleRequest

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module BundleProp : sig

  type t = bundleProp

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

  val length_func : Cstruct.t -> int option

end

module BundleCtrl : sig

  type t = bundleCtrl

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module BundleAdd : sig

  val sizeof : 'a bundleAdd -> ('a -> int) -> int

  val to_string : 'a bundleAdd -> ('a -> string) -> string

  val marshal : Cstruct.t -> 'a bundleAdd -> ('a -> Cstruct.t -> int) -> (xid -> 'a -> OpenFlow_Header.t) -> int

  val parse : Cstruct.t -> (OpenFlow_Header.t -> string -> xid * 'a) -> ('a -> int) -> 'a bundleAdd

end

module AsyncConfig : sig

  module Properties : sig

    type t = asyncProp

    val sizeof : t -> int

    val to_string : t -> string

    val marshal : Cstruct.t -> t -> int

    val parse : Cstruct.t -> t

    val length_func : Cstruct.t -> int option

  end

  type t = asyncConfig

  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module PacketIn : sig

  type t = packetIn
  
  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module PortStatus : sig

  type t = portStatus
  
  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module RoleStatus : sig

  module Properties : sig

    type t = roleStatusProp

    val sizeof : t -> int

    val to_string : t -> string

    val marshal : Cstruct.t -> t -> int

    val parse : Cstruct.t -> t

  end

  type t = roleStatus
  
  val sizeof : t -> int

  val to_string : t -> string

  val marshal : Cstruct.t -> t -> int

  val parse : Cstruct.t -> t

end

module TableStatus : sig

  type t = tableStatus
  
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
    | PortModMsg of PortMod.t
    | MeterModMsg of MeterMod.t
    | MultipartReq of MultipartReq.t
    | MultipartReply of MultipartReply.t
    | BarrierRequest
    | BarrierReply
    | PacketOutMsg of PacketOut.t
    | RoleRequest of RoleRequest.t
    | RoleReply of RoleRequest.t
    | BundleControl of BundleCtrl.t
    | BundleAdd of t bundleAdd
    | GetAsyncRequest
    | GetAsyncReply of AsyncConfig.t
    | SetAsync of AsyncConfig.t
    | PacketInMsg of PacketIn.t
    | PortStatus of PortStatus.t
    | RoleStatus of RoleStatus.t
    | TableStatus of TableStatus.t
    | RequestForward of t requestForward

  val sizeof : t -> int

  val to_string : t -> string

  val blit_message : t -> Cstruct.t -> int
  
  val header_of : xid -> t -> OpenFlow_Header.t

  val marshal : xid -> t -> string

  val parse : OpenFlow_Header.t -> string -> (xid * t)
  
  val marshal_body : t -> Cstruct.t -> unit
   
end
