module Sw = OpenFlow0x04_Switch
open OpenFlow0x04_Core
open OpenFlow0x04.Message

let config_switch sw = 
	let send = Sw.send sw 0l in
	let setBits0 = OxmVlanVId  { m_value = 0xFFF;
	                            m_mask = None } in

	let setBits = OxmVlanVId  { m_value = 0x0AA;
	                            m_mask = Some 0x000 } in
	let actions = [PushVlan; SetField setBits0; SetField setBits; Output AllPorts] in
	lwt _ = send (FlowModMsg delete_all_flows) in
	lwt _ = send (FlowModMsg (add_flow 500 [] [ApplyActions actions])) in
	Format.eprintf "Configured switch to set fragment of dlSrc header.\n%!";
	Lwt.return ()

let main () =
	Lwt_main.run
  (Format.eprintf "Running OpenFlow 1.3 masking demo...\n%!";
  let open Lwt_unix in
  let server_fd = socket PF_INET SOCK_STREAM 0 in
  setsockopt server_fd SO_REUSEADDR true;
  bind server_fd (ADDR_INET (Unix.inet_addr_any, 6633));
  listen server_fd 100;
  let rec accept_loop () =
    lwt (fd, sa) = Lwt_unix.accept server_fd in
    match_lwt HighLevelSwitch.recv_hello_from_switch fd with
    | Some 0x04 -> (match_lwt Sw.handshake fd with
      | None -> Format.eprintf "Switch disconnected.\n%!"; accept_loop ()
      | Some sw -> lwt _ = config_switch sw in accept_loop ())
    | Some ver -> 
      Format.eprintf "Switch connected has version %x.\n%!" ver;
      accept_loop ()
    | None ->
        Format.eprintf "Switch did not send hello\n%!";
        accept_loop () in
  accept_loop ())

