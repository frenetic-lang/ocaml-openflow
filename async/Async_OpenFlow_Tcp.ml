open Async.Std
open Core.Std

module type Message = Async_OpenFlow_Message.Message

exception Flush_closed_writer


module Make(Message : Message) : Typed_tcp.S
  with type Server_message.t = Message.t
  and type Client_message.t = Message.t = Typed_tcp.Make(struct

  module Client_message = Message
  module Server_message = Message

  module Serialization = Async_OpenFlow_Message.MakeSerializers (Message)

  module Transport = struct

    type t = Reader.t * Writer.t

    let create (r : Reader.t) (w : Writer.t) = return (r, w)

    let close ((_, w) : t) = Writer.close w

    let flushed_time ((_, w) : t) =
      let open Deferred in
      choose [ choice (Writer.flushed_time  w) (fun x  -> `F x)
             ; choice (Writer.consumer_left w) (fun () -> `C ())
             ]
      >>| function
        | `F x -> x
        | `C () -> raise Flush_closed_writer

    let read ((r, _) : t) = Serialization.deserialize r

    let write ((_, w) : t) (m : Message.t) : unit = Serialization.serialize w m

  end

end)