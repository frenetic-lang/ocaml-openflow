open Async.Std
open Core.Std

module Header = OpenFlow_Header
module type Message = Async_OpenFlow_Message.Message

module type S = sig

  type t 
  type m

  module Client_id : Unique_id

  type e = [
    | `Connect of Client_id.t
    | `Disconnect of Client_id.t * Sexp.t
    | `Message of Client_id.t * m
  ]

  val create
    :  ?max_pending_connections:int
    -> ?verbose:bool
    -> ?log_disconnects:bool
    -> ?buffer_age_limit:[ `At_most of Time.Span.t | `Unlimited ]
    -> port:int
    -> unit
    -> t Deferred.t

  val listen : t -> e Pipe.Reader.t

  val close : t -> Client_id.t -> unit

  val has_switch_id : t -> Client_id.t -> bool

  val send 
    : t
    -> Client_id.t
    -> m
    -> [ `Drop of exn | `Sent of Time.t ] Deferred.t

  val send_to_all : t -> m -> unit

  val client_addr_port 
    :  t 
    -> Client_id.t
    -> (Unix.Inet_addr.t * int) option

  val listening_port : t -> int

end


module Make(Message : Message) = struct

  type m = Message.t

  module Impl = Typed_tcp.Make(struct

    module Client_message = Message
    module Server_message = Message

    module Serialization = Async_OpenFlow_Message.MakeSerializers (Message)

    module Transport = struct

      type t = Reader.t * Writer.t

      let create (r : Reader.t) (w : Writer.t) = return (r, w)

      let close ((_, w) : t) = Writer.close w

      let flushed_time ((_, w) : t) = Writer.flushed_time w

      let read ((r, _) : t) = Serialization.deserialize r

      let write ((_, w) : t) (m : m) : unit = Serialization.serialize w m

    end
  
  end)

  type t = Impl.t

  module Client_id =  Impl.Client_id

  type e = [
    | `Connect of Client_id.t
    | `Disconnect of Client_id.t * Sexp.t
    | `Message of Client_id.t * m
  ]

  let create ?max_pending_connections
      ?verbose
      ?log_disconnects
      ?buffer_age_limit ~port () =
    Impl.create ?max_pending_connections ?verbose ?log_disconnects
      ?buffer_age_limit ~port ~auth:(fun _ _ -> return `Allow) ()

  let listen t =
    let open Impl.Server_read_result in
    Pipe.map (Impl.listen t)
    ~f:(function
        | Connect id -> `Connect id
        | Disconnect (id, sexp) -> `Disconnect (id, sexp)
        | Denied_access msg -> raise (Invalid_argument "Denied_access should not happen")
        | Data (id, m) -> `Message (id, m))

  let close = Impl.close

  let has_switch_id = Impl.has_client_id

  let send = Impl.send

  let send_to_all = Impl.send_to_all

  let client_addr_port = Impl.client_addr_port

  let listening_port = Impl.port

end

module Trans = struct
  type ('t, 'a, 'b) stage = 't -> 'a -> 'b option Deferred.t

  let compose (f : ('t, 'b, 'c) stage) (g : ('t, 'a, 'b) stage) : ('t, 'a, 'c) stage =
    fun t e ->
      g t e
      >>= function
        | Some e' -> f t e'
        | None -> return None

  let (>=>) f g = compose g f
  let (<=<) f g = compose f g

  let local (l : 't1 -> 't2) (f : ('t2, 'a, 'b) stage) : ('t1, 'a, 'b) stage =
    fun t e -> f (l t) e

  let run (f : ('t, 'a, 'b) stage) (t : 't) (r : 'a Pipe.Reader.t) : 'b Pipe.Reader.t =
    Pipe.filter_map' r ~f:(f t)
end
