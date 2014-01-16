open Async.Std
open Core.Std

open OpenFlow0x01
open OpenFlow0x01_Core
open OpenFlow0x01.Message
open OpenFlow_Header

module OF0x01Controller = Async_OpenFlow0x01.Controller
module Log = Async_OpenFlow.Log

let f t = function
  | `Connect client_id -> Log.info "connect"; 
        OF0x01Controller.send t client_id (0l, Hello (Cstruct.of_string ""))
        >>= fun _ ->
        return ()
     (*   >>| ensure *)
  | `Message _ -> Log.info "message"; return ()
  | `Disconnect (client_id, _) -> Log.info "disconnect"; return ()

let main () =
  let port = 6633 in
  let open OF0x01Controller in
  create ~max_pending_connections:64 ~verbose:true ~log_disconnects:true ~port ()
  >>= fun t ->
  Pipe.iter (listen t) ~f:(f t)

let _ = main ()
let _ = never_returns (Scheduler.go ())
