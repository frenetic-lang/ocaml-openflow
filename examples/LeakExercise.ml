open Async.Std
open Core.Std

open OpenFlow0x01
open OpenFlow0x01_Core
open OpenFlow0x01.Message

module OF0x01Controller = Async_OpenFlow0x01.Controller
module Log = Async_OpenFlow.Log

let f t = function
  | `Connect client_id ->
      OF0x01Controller.send t client_id (0l, Hello (Cstruct.of_string ""))
        >>= fun _ ->
        return ()
  | `Message _ -> return ()
  | `Disconnect (client_id, _) -> Log.info "disconnect"; return ()

let main () =
  let open OF0x01Controller in
  create 6633
  >>= fun t ->
  Pipe.iter (listen t) ~f:(f t)

let _ = main ()
let _ = never_returns (Scheduler.go ())
