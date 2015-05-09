open Core.Std

module Platform = Async_OpenFlow_Platform
module Header = OpenFlow_Header
module M = OpenFlow0x01.Message
module C = OpenFlow0x01_Core

module Message : Platform.Message with type t = (OpenFlow0x01.xid * M.t) = struct

  type t = (OpenFlow0x01.xid * M.t) sexp_opaque with sexp

  let header_of (xid, m) = M.header_of xid m
  let parse hdr buf = M.parse hdr (Cstruct.to_string buf)
  let marshal (xid, m) buf = M.marshal_body m buf
  let to_string (_, m) = M.to_string m

  let marshal' msg =
    let hdr = header_of msg in
    let body_len = hdr.Header.length - Header.size in
    let body_buf = Cstruct.create body_len in
    marshal msg body_buf;
    (hdr, body_buf)

end

include Async_OpenFlow_Message.MakeSerializers (Message)

module ControllerProcess = struct
  open Async.Std
  open Async_parallel

  (* Note: because we run in a different process, the settings for Log have to be transferred explicitly (i.e. this defaults to level:`Info, even if we set it to `Debug somewhere else *)
  module Log = Async_OpenFlow_Log
  let tags = [("openflow", "openflow0x01")]

  module ChunkController = Async_OpenFlowChunk.Controller
  module Client_id = struct
    module T = struct
      type t = SDN_Types.switchId with sexp
      let compare = compare
      let hash = Hashtbl.hash
    end
    include T
    include Hashable.Make(T)
  end


  module ClientMap = ChunkController.Client_id.Table
  module ClientSet = ChunkController.Client_id.Hash_set
  module SwitchMap = Client_id.Table

  type m = Message.t
  type c = OpenFlow0x01.SwitchFeatures.t
  type t = {
    sub : ChunkController.t;
    shakes : ClientSet.t;
    c2s : SDN_Types.switchId ClientMap.t;
    s2c : ChunkController.Client_id.t SwitchMap.t;
  }

  type e = (Client_id.t, c, m) Platform.event


  let set_monitor_interval (t:t) (s:Time.Span.t) : unit =
    ChunkController.set_monitor_interval t.sub s

  let set_idle_wait (t:t) (s:Time.Span.t) : unit =
    ChunkController.set_idle_wait t.sub s

  let set_kill_wait (t:t) (s:Time.Span.t) : unit =
    ChunkController.set_kill_wait t.sub s


  (* XXX(seliopou): Raises `Not_found` if the client is no longer connected. *)
  let switch_id_of_client_exn t c_id = ClientMap.find_exn t.c2s c_id
  let client_id_of_switch_exn t sw_id = SwitchMap.find_exn t.s2c sw_id

  let switch_id_of_client t c_id = ClientMap.find t.c2s c_id
  let client_id_of_switch t sw_id = SwitchMap.find t.s2c sw_id

  let close t sw_id =
    let c_id = client_id_of_switch_exn t sw_id in
    ChunkController.close t.sub c_id

  let has_client_id t sw_id =
    let c_id = client_id_of_switch_exn t sw_id in
    ChunkController.has_client_id t.sub c_id

  let get_switches t = SwitchMap.keys t.s2c

  let send t sw_id msg =
    let c_id = client_id_of_switch_exn t sw_id in
    ChunkController.send t.sub c_id (Message.marshal' msg)

  let send_result t sw_id msg =
    send t sw_id msg
    >>| function
      | `Sent t   -> Result.Ok ()
      | `Drop exn -> Result.Error exn

  let send_txn t sw_id msg =
    let c_id = client_id_of_switch_exn t sw_id in
    let xid  = ChunkController.client_next_xid t.sub c_id in
    ChunkController.send_txn t.sub c_id (Message.marshal' (xid, msg))

  let send_txn_with t sw_id msg f =
    try begin
      send_txn t sw_id msg
      >>= function
        | `Sent def -> def >>| f
        | `Drop exn -> return (Result.Error exn)
    end with Not_found -> return (Result.Error Not_found)

  let send_ignore_errors t sw_id msg =
    let c_id = client_id_of_switch_exn t sw_id in
    ChunkController.send_ignore_errors t.sub c_id (Message.marshal' msg)

  let send_to_all t msg =
    ChunkController.send_to_all t.sub (Message.marshal' msg)

  let client_addr_port t sw_id =
    let c_id = client_id_of_switch_exn t sw_id in
    ChunkController.client_addr_port t.sub c_id

  let listening_port t =
    ChunkController.listening_port t.sub

  let openflow0x01 t evt =
    match evt with
      | `Connect (c_id, version) ->
        if version = 0x01 then
          return [`Connect c_id]
        else begin
          ChunkController.close t.sub c_id;
          raise (ChunkController.Handshake (c_id, Printf.sprintf
                    "Negotiated switch version mismatch: expected %d but got %d%!"
                    0x01 version))
        end
      | `Message (c_id, (hdr, bits)) ->
        return [`Message (c_id, Message.parse hdr bits)]
      | `Disconnect e -> return [`Disconnect e]

  let features t evt =
    match evt with
      | `Connect (c_id) ->
        assert (not (Hash_set.mem t.shakes c_id));
        Hash_set.add t.shakes c_id;
        ChunkController.send t.sub c_id (Message.marshal' (0l, M.SwitchFeaturesRequest))
        (* XXX(seliopou): This swallows any errors that might have occurred
         * while attemping the handshake. Any such error should not be raised,
         * since as far as the user is concerned the connection never existed.
         * At the very least, the exception should be logged, which it will be
         * as long as the log_disconnects option is not disabled when creating
         * the controller.
         * *)
        >>| (function _ -> [])
      | `Message (c_id, (xid, msg)) when Hash_set.mem t.shakes c_id ->
        begin match msg with
          | M.SwitchFeaturesReply fs ->
            let switch_id = fs.OpenFlow0x01.SwitchFeatures.switch_id in
            ClientMap.add_exn t.c2s c_id switch_id;
            SwitchMap.add_exn t.s2c switch_id c_id;
            Hash_set.remove t.shakes c_id;
            return [`Connect(switch_id, fs)]
          | _ ->
            Log.printf ~tags ~level:`Debug
              "Dropped message during handshake: %s"
                (Message.to_string (xid, msg));
            return []
        end
      | `Message (c_id, msg) ->
        return [`Message(switch_id_of_client_exn t c_id, msg)]
      | `Disconnect (c_id, exn) ->
        match switch_id_of_client t c_id with
          | None -> (* features request did not complete *)
            assert (Hash_set.mem t.shakes c_id);
            Hash_set.remove t.shakes c_id;
            return []
          | Some(sw_id) -> (* features request did complete *)
            ClientMap.remove t.c2s c_id;
            SwitchMap.remove t.s2c sw_id;
            return [`Disconnect(sw_id, exn)]

  let listen_pipe t p =
    let open Async_OpenFlow_Stage in
    run (openflow0x01 >=> features) t p

  let listen t =
    let open Async_OpenFlow_Stage in
    let open ChunkController in
    listen_pipe t (run (handshake 0x01) t.sub (listen t.sub))

  let clear_flows ?(pattern=C.match_all) (t:t) (sw_id:Client_id.t) =
    send_result t sw_id (0l, M.FlowModMsg
      { C.delete_all_flows with C.pattern = pattern })

  let send_flow_mods ?(clear=true) (t:t) (sw_id:Client_id.t) flow_mods =
    let open Deferred.Result in
    begin if clear then clear_flows t sw_id else return () end
    >>= fun () ->
      Deferred.(List.map flow_mods
        ~f:(fun f -> send_result t sw_id (0l, M.FlowModMsg f))
    >>| (fun sends ->
    Core.Std.Result.all_ignore sends))

  let send_pkt_out (t:t) (sw_id:Client_id.t) pkt_out =
    send_result t sw_id (0l, M.PacketOutMsg pkt_out)

  let barrier t sw_id =
    send_txn_with t sw_id M.BarrierRequest (function
      | `Result (hdr, _) -> Result.Ok () (* assume it is a barrier reply *)
      | _              -> assert false)

  let aggregate_stats ?(pattern=C.match_all) (t:t) sw_id =
    let open OpenFlow0x01_Stats in
    let msg = AggregateRequest
      { sr_of_match = pattern
      ; sr_table_id = 0xff
      ; sr_out_port = None }
    in
    send_txn_with t sw_id (M.StatsRequestMsg msg) (function
      | `Result (hdr, body) ->
         (match M.parse hdr (Cstruct.to_string body) with
          | (_, M.StatsReplyMsg (AggregateFlowRep r)) -> Result.Ok r
          | _ -> assert false)
      | _                                    -> assert false)

  let individual_stats ?(pattern=C.match_all) (t:t) sw_id =
    let open OpenFlow0x01_Stats in
    let msg = IndividualRequest
      { sr_of_match = pattern
      ; sr_table_id = 0xff
      ; sr_out_port = None }
    in
    send_txn_with t sw_id (M.StatsRequestMsg msg) (function
      | `Result (hdr, body) ->
        (match M.parse hdr (Cstruct.to_string body) with
         | (_, M.StatsReplyMsg (IndividualFlowRep r)) -> Result.Ok r
         | _ -> assert false)
      | _ -> assert false)

  let launch_cpu_process () =
    don't_wait_for (Pipe.iter_without_pushback (Cpu_usage.samples ()) 
      ~f:(fun pct -> Log.printf ~tags ~level:`Info "[remote] %s CPU usage" (Percent.to_string pct)))

  let create_from_chunk t =
    { sub = t
    ; shakes = ClientSet.create ()
    ; c2s = ClientMap.create ()
    ; s2c = SwitchMap.create ()
    }

    let create_from_chunk_hub t h =
      launch_cpu_process ();
      let ctl = create_from_chunk t in
      Pipe.iter (Hub.listen_simple h) ~f:(fun (id, msg) -> match msg with
        | `Send (sw_id, msg) -> begin
            Log.debug ~tags "[remote] send";
            send ctl sw_id msg
            >>| fun resp -> Hub.send h id (`Send_resp resp)
          end
        | `Send_to_all msg ->
          Log.debug ~tags "[remote] send_to_all";
          return (send_to_all ctl msg)
        | `Send_ignore_errors (sw_id, msg) ->
            return (send_ignore_errors ctl sw_id msg)
        | `Listen -> begin
            Intf.hub ~buffer_age_limit:`Unlimited ()
            >>= fun new_h ->
            Deferred.don't_wait_for (Pipe.read (Hub.listen_simple new_h)
                                     >>= function
                                     | `Ok (id, msg) ->
                                       (Pipe.iter_without_pushback (listen ctl)
                                          ~f:(Hub.send new_h id)));
            Hub.open_channel new_h
            >>| fun chan -> Hub.send h id (`Listen_resp chan)
          end
        | `Individual_stats (pattern, sw_id) -> (individual_stats ctl ~pattern sw_id)
          >>| fun resp -> Hub.send h id (`Individual_stats_resp resp)
        | `Barrier args -> barrier ctl args
          >>| fun resp -> Hub.send h id (`Barrier_resp resp)
        | `Close sw_id -> return (close ctl sw_id)
        | `Has_client_id sw_id -> has_client_id ctl sw_id
          >>| fun resp -> Hub.send h id (`Has_client_id_resp resp)
        | `Client_addr_port sw_id -> client_addr_port ctl sw_id
          >>| fun resp -> Hub.send h id (`Client_addr_port_resp resp)
        | `Listening_port -> listening_port ctl
          >>| fun resp -> Hub.send h id (`Listening_port_resp resp)
        | `Set_monitor_interval interval -> return (set_monitor_interval ctl interval)
        | `Set_idle_wait interval -> return (set_idle_wait ctl interval)
        | `Set_kill_wait interval -> return (set_kill_wait ctl interval)
        | `Get_switches ->
          Log.debug ~tags "[remote] get_switches";
          return (Hub.send h id (`Get_switches_resp (get_switches ctl)))
        | `Clear_flows (pattern, sw_id) -> clear_flows ~pattern ctl sw_id
          >>| fun resp -> Hub.send h id (`Clear_flows_resp resp)
        | `Send_flow_mods (clear, sw_id, flow_mods) -> 
          Log.debug ~tags "[remote] send_flow_mods";
          send_flow_mods ~clear ctl sw_id flow_mods
          >>| fun resp -> Hub.send h id (`Send_flow_mods_resp resp)
        | `Send_pkt_out (sw_id, pkt_out) -> send_pkt_out ctl sw_id pkt_out
          >>| fun resp -> Hub.send h id (`Send_pkt_out_resp resp)
        | `Aggregate_stats (pattern, sw_id) -> aggregate_stats ~pattern ctl sw_id
          >>| fun resp -> Hub.send h id (`Aggregate_stats_resp resp)

      )

  let create ?max_pending_connections
      ?verbose
      ?log_disconnects
      ?buffer_age_limit
      ?monitor_connections
      ?log_level ~port h =
    ChunkController.create ?max_pending_connections ?verbose ?log_disconnects
      ?buffer_age_limit ?monitor_connections ?log_level ~port ()
    >>= (fun t -> create_from_chunk_hub t h)

end

module Controller = struct
  open ControllerProcess
  open Async.Std
  open Async_parallel

  module Log = Async_OpenFlow_Log
  let tags = [("openflow", "openflow0x01")]

  (* We can not call read() on the same pipe concurrently. 
     Somehow this is happening sometimes, so we need to 
     enforce this invariant locally with condition variables. *)

  let read_outstanding = ref false

  let read_finished = Condition.create ()

  module Client_id = ControllerProcess.Client_id
  type t = ([ `Barrier of SwitchMap.key
            | `Individual_stats of
                C.pattern *
                SwitchMap.key
            | `Listen
            | `Send of
                SwitchMap.key *
                Message.t
            | `Send_to_all of
                Message.t
            | `Send_ignore_errors of
                SwitchMap.key *
                Message.t
            | `Close of Client_id.t
            | `Has_client_id of Client_id.t
            | `Client_addr_port of Client_id.t
            | `Listening_port
            | `Set_monitor_interval of Core.Std.Time.Span.t
            | `Set_idle_wait of Core.Std.Time.Span.t
            | `Set_kill_wait of Core.Std.Time.Span.t
            | `Get_switches
            | `Clear_flows of OpenFlow0x01_Core.pattern * Client_id.t
            | `Send_flow_mods of bool * Client_id.t * OpenFlow0x01_Core.flowMod list
            | `Send_pkt_out of Client_id.t * OpenFlow0x01_Core.packetOut
            | `Aggregate_stats of OpenFlow0x01_Core.pattern * Client_id.t
            ],
            [ `Barrier_resp of (unit, exn) Result.t
            | `Individual_stats_resp of
                (OpenFlow0x01_Stats.individualStats list, exn) Result.t
            | `Listen_resp of
                ([ `Ready ],
                 [ `Connect of
                     OpenFlow0x01.switchId * OpenFlow0x01.SwitchFeatures.t
                 | `Disconnect of SDN_Types.switchId * Core.Std.Sexp.t
                 | `Message of
                     SDN_Types.switchId * Message.t]) Channel.t
            | `Send_resp of [ `Drop of exn | `Sent of Time.t ]
            | `Has_client_id_resp of bool
            | `Client_addr_port_resp of (Unix.Inet_addr.t * int) option
            | `Listening_port_resp of int
            | `Get_switches_resp of SDN_Types.switchId list
            | `Clear_flows_resp of (unit, exn) Result.t
            | `Send_flow_mods_resp of (unit, exn) Result.t
            | `Send_pkt_out_resp of (unit, exn) Result.t
            | `Aggregate_stats_resp of (OpenFlow0x01_Stats.aggregateStats, exn) Result.t
            ]) Channel.t
  let rec clear_to_read () = if (!read_outstanding)
    then Condition.wait read_finished >>= clear_to_read
    else return (read_outstanding := true)

  let signal_read () = read_outstanding := false; 
    Condition.broadcast read_finished ()

  let aggregate_stats ?(pattern=C.match_all) (t : t) sw_id =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] aggregate_stats";
    Channel.write t (`Aggregate_stats (pattern, sw_id));
    Channel.read t >>| function
    | `Aggregate_stats_resp resp -> signal_read (); resp

  let send_pkt_out (t : t) (sw_id:Client_id.t) pkt_out =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] send_pkt_out";
    Channel.write t (`Send_pkt_out (sw_id, pkt_out));
    Channel.read t >>| function
    | `Send_pkt_out_resp resp -> signal_read (); resp

  let send_flow_mods ?(clear=true) (t : t) (sw_id:Client_id.t) flow_mods =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] send_flow_mods";
    Channel.write t (`Send_flow_mods (clear, sw_id, flow_mods));
    Channel.read t >>| function
    | `Send_flow_mods_resp resp -> signal_read (); resp

  let clear_flows ?(pattern=C.match_all) (t : t) (sw_id:Client_id.t) =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] clear_flows";
    Channel.write t (`Clear_flows (pattern, sw_id));
    Channel.read t >>| function
    | `Clear_flows_resp resp -> signal_read (); resp

  let get_switches (t : t) =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] get_switches";
    Channel.write t `Get_switches;
    Channel.read t >>| function
    | `Get_switches_resp resp -> signal_read (); resp

  let set_kill_wait t (s:Time.Span.t) =
    Log.debug ~tags "[local] set_kill_wait";
    Channel.write t (`Set_kill_wait s)

  let set_monitor_interval t (s:Time.Span.t) =
    Log.debug ~tags "[local] set_monitor_interval";
    Channel.write t (`Set_monitor_interval s)

  let set_idle_wait t (s:Time.Span.t) : unit =
    Log.debug ~tags "[local] set_idle_wait";
    Channel.write t (`Set_idle_wait s)

  let listening_port (t : t) =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] set_listening_port";
    Channel.write t `Listening_port;
    Channel.read t >>| function
    | `Listening_port_resp resp -> signal_read (); resp

  let client_addr_port (t : t) sw_id =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] client_addr_port";
    Channel.write t (`Client_addr_port sw_id);
    Channel.read t >>| function
    | `Client_addr_port_resp resp -> signal_read (); resp

  let send_to_all (t : t) msg =
    Log.debug ~tags "[local] send_to_all";
    Channel.write t (`Send_to_all msg)

  let send_ignore_errors (t : t) sw_id msg =
    Log.debug ~tags "[local] send_ignore_errors";
    Channel.write t (`Send_ignore_errors (sw_id, msg))

  let has_client_id (t : t) sw_id =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] has_client_id";
    Channel.write t (`Has_client_id sw_id);
    Channel.read t >>| function
    | `Has_client_id_resp resp -> signal_read (); resp

  let close (t : t) sw_id =
    Log.debug ~tags "[local] close";
    Channel.write t (`Close sw_id)

  type e = ControllerProcess.e
  type m = ControllerProcess.m
  type c = ControllerProcess.c

  let create_from_chunk chunk =
    Log.debug ~tags "[local] create_from_chunk";
    Intf.spawn (create_from_chunk_hub chunk) >>| fun (c,_) ->
    c

  let create ?max_pending_connections
      ?verbose
      ?log_disconnects
      ?buffer_age_limit
      ?monitor_connections
      ?log_level
      ~port () : t Deferred.t =
    Log.debug ~tags "[local] create";
    Intf.spawn (create ?max_pending_connections
      ?verbose
      ?log_disconnects
      ?buffer_age_limit
      ?monitor_connections
      ?log_level ~port) >>| fun (c,_) ->
    c

  let send (t : t) sw_id msg =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] send";
    Channel.write t (`Send (sw_id, msg));
    Channel.read t >>| function
    | `Send_resp resp -> signal_read (); resp

  let channel_transfer chan writer =
    Deferred.forever () (fun _ -> Channel.read chan >>=
                          Pipe.write writer)
  let listen (t : t) =
    Log.debug ~tags "[local] listen";
    Channel.write t `Listen;
    let reader,writer = Pipe.create () in
    don't_wait_for (
      clear_to_read () >>= fun () ->
      Log.debug ~tags "[local] About to listen for listen_resp";
      Channel.read t >>| function
      | `Listen_resp chan -> Log.debug ~tags "[local] Listen channel returned";
        signal_read ();
        Channel.write chan `Ready;
        channel_transfer chan writer);
    reader

  let barrier (t : t) sw_id =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] barrier";
    Channel.write t (`Barrier sw_id);
    Channel.read t >>| function
    | `Barrier_resp resp -> signal_read (); resp

  let individual_stats ?(pattern=C.match_all) (t : t) sw_id =
    clear_to_read () >>= fun () ->
    Log.debug ~tags "[local] individual_stats";
    Channel.write t (`Individual_stats (pattern, sw_id));
    Channel.read t >>| function
    | `Individual_stats_resp resp -> signal_read (); resp
end
