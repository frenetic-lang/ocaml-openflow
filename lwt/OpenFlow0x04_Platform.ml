open Socket
open OpenFlow0x04_Core
open OpenFlow0x04

open Lwt
open Lwt_io
open Lwt_unix
open Lwt_list

module Log = Lwt_log

let sprintf = Format.sprintf

module type PLATFORM = sig
  exception SwitchDisconnected of switchId 
  val send_to_switch : switchId -> xid -> Message.t -> unit t
  val recv_from_switch : switchId -> (xid * Message.t) t
  val accept_switch : unit -> (SwitchFeatures.t * portDesc list) t
end

module OpenFlowPlatform = struct
  exception SwitchDisconnected of switchId 
  exception UnknownSwitch of switchId
  exception UnknownSwitchDisconnected 
  exception Internal of string

  let server_fd : file_descr option ref = 
    ref None

  let init_with_fd (fd : file_descr) : unit = 
    match !server_fd with
    | Some _ -> 
      raise (Internal "Platform already initialized")
    | None -> 
      server_fd := Some fd

  let init_with_port (p : int) : unit = 
    match !server_fd with
    | Some _ -> 
      raise (Internal "Platform already initialized")
    | None -> 
      let fd = socket PF_INET SOCK_STREAM 0 in
      setsockopt fd SO_REUSEADDR true;
      bind fd (ADDR_INET (Unix.inet_addr_any, p));
      listen fd 64; (* JNF: 640K ought to be enough for anybody. *)
      server_fd := Some fd

  let get_fd () = 
    match !server_fd with
    | Some fd -> 
      fd
    | None -> 
      raise (Invalid_argument "Platform not initialized")

  (** Receives an OpenFlow message from a raw file. Does not update
      any controller state. *)
  let rec recv_from_switch_fd (sock : file_descr) : (xid * Message.t) Lwt.t = 
    let ofhdr_str = String.create Message.Header.size in
    lwt b = OpenFlow0x04_Misc.SafeSocket.recv sock ofhdr_str 0 Message.Header.size in 
    if not b then 
      raise_lwt UnknownSwitchDisconnected
    else  
      let hdr = Message.Header.parse ofhdr_str in
      let sizeof_body = hdr.Message.Header.len - Message.Header.size in
      let body_str = String.create sizeof_body in
      lwt b = OpenFlow0x04_Misc.SafeSocket.recv sock body_str 0 sizeof_body in 
      if not b then 
        raise_lwt UnknownSwitchDisconnected
      else
        begin
          lwt () = Log.notice_f "[platform] returning message with code %s\n%!"
            (Message.string_of_msg_code hdr.Message.Header.typ) in
          lwt msg = Lwt.wrap (fun () -> Message.parse hdr body_str) in
          return msg
        end
  
  let send_to_switch_fd (sock : file_descr) (xid : xid) (msg : Message.t) = 
    try_lwt
      lwt out = Lwt.wrap2 Message.marshal xid msg in
      let len = String.length out in
      lwt n = write sock out 0 len in
      if n <> len then
        raise_lwt (Internal "[send_to_switch] not enough bytes written")
      else 
        return ()
    with Unix.Unix_error (err, fn, arg) ->
      lwt () = Log.error_f "[platform] error sending: %s (in %s)\n%!"
        (Unix.error_message err) fn in
      return ()

  let switch_fds : (switchId, file_descr) Hashtbl.t = 
    Hashtbl.create 100

  let fd_of_switch_id (switch_id:switchId) : file_descr = 
    try Hashtbl.find switch_fds switch_id 
    with Not_found -> raise (UnknownSwitch switch_id)

  let disconnect_switch (sw_id : switchId) = 
    lwt () = Log.debug_f "[platform] disconnect_switch\n%!" in
    try_lwt
      let fd = Hashtbl.find switch_fds sw_id in
      lwt _ = close fd in
      Hashtbl.remove switch_fds sw_id;
      return ()
    with Not_found ->
      begin
        lwt () = Log.error_f "[disconnect_switch] switch not found\n%!" in
        raise_lwt (UnknownSwitch sw_id)
      end

  let shutdown () : unit = 
    ignore_result (Log.notice_f "[platform] shutdown\n%!");
    match !server_fd with 
    | Some fd -> 
      ignore_result 
	begin 
	  lwt _ = iter_p (fun fd -> close fd)
            (Hashtbl.fold (fun _ fd l -> fd::l) switch_fds []) in 
	  return ()
	end
    | None -> 
       ()

  let switch_handshake (fd : file_descr) : (SwitchFeatures.t * portDesc list) Lwt.t = 
    let open Message in
    lwt () = Log.debug_f "[platform] switch_handshake\n%!" in
    lwt _ = send_to_switch_fd fd 0l Hello in
    lwt () = Log.debug_f "[platform] trying to read Hello\n%!" in
    lwt (xid, msg) = recv_from_switch_fd fd in
    match msg with
      | Hello -> 
        lwt () = Log.debug_f "[platform] sending Features Request\n%!" in
        lwt _ = send_to_switch_fd fd 0l FeaturesRequest in
        lwt (_, msg) = recv_from_switch_fd fd in
        begin
          match msg with
            | FeaturesReply feats ->
              Hashtbl.add switch_fds feats.SwitchFeatures.datapath_id fd;
              lwt () = Log.debug_f "[platform] switch %Ld connected\n%!"
                feats.SwitchFeatures.datapath_id in
              lwt () = Log.debug_f "[platform] sending Ports Request\n%!" in
              lwt _ = send_to_switch_fd fd 0l portsDescRequest in
              lwt (_, msg) = recv_from_switch_fd fd in
              begin
		match msg with
		  | MultipartReply (PortsDescReply ports) ->
		    return (feats, ports)
		  | _ -> raise_lwt (Internal "expected PORT_DESC_REPLY")
              end 
            | _ -> raise_lwt (Internal "expected FEATURES_REPLY")
        end 
      | _ -> raise_lwt (Internal "expected Hello")

  let send_to_switch (sw_id : switchId) (xid : xid) (msg : Message.t) : unit t = 
    lwt () = Log.debug_f "[platform] send_to_switch\n%!" in
    let fd = fd_of_switch_id sw_id in
    try_lwt 
      send_to_switch_fd fd xid msg
    with Internal s ->
      lwt _ = disconnect_switch sw_id in
      raise_lwt (SwitchDisconnected sw_id)

  (* By handling echoes here, we do not respond to echoes during the
     handshake. *)
  let rec recv_from_switch (sw_id : switchId) : (xid * Message.t) t = 
    lwt () = Log.debug_f "[platform] recv_from_switch\n%!" in
    let switch_fd = fd_of_switch_id sw_id in
    lwt (xid, msg) = 
      try_lwt
        recv_from_switch_fd switch_fd
      with 
      | Internal s ->
        begin
          lwt () = Log.error_f "[platform] disconnecting switch\n%!" in
          lwt _ = disconnect_switch sw_id in
          raise_lwt (SwitchDisconnected sw_id)
        end 
      | UnknownSwitchDisconnected -> 
	  raise_lwt (SwitchDisconnected sw_id)
      | exn -> 
        lwt () = Log.error_f "[platform] other error\n%!" in
          raise_lwt exn in 
    match msg with
      | Message.EchoRequest bytes -> 
        send_to_switch sw_id xid (Message.EchoReply bytes) >>
        recv_from_switch sw_id
      | _ -> return (xid, msg)

  let rec accept_switch () = 
    lwt () = Log.notice_f "[platform] accept_switch\n%!" in
    lwt (fd, sa) = accept (get_fd ()) in
    lwt () = Log.notice_f "[platform] : %s connected, handshaking...\n%!"
      (string_of_sockaddr sa) in
    (* TODO(arjun): a switch can stall during a handshake, while another
       switch is ready to connect. To be fully robust, this module should
       have a dedicated thread to accept TCP connections, a thread per new
       connection to handle handshakes, and a queue of accepted switches.
       Then, accept_switch will simply dequeue (or block if the queue is
       empty). *)
     try_lwt
       switch_handshake fd
     with UnknownSwitchDisconnected -> 
      begin
        lwt _ = close fd in
        lwt () = Log.notice_f "[platform] : %s disconnected, trying again...\n%!"
            (string_of_sockaddr sa) in
        accept_switch ()
       end
end
