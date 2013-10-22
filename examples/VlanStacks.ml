module Sw = OpenFlow0x04_Switch
open OpenFlow0x04_Core
open OpenFlow0x04.Message

let match_vlan n = 
  OxmVlanVId { m_value = n; m_mask = None }

let push_vlan n =
    [ PushVlan; SetField (match_vlan n) ]

let rec push_vlans min max =
    if min < max then push_vlan min @ push_vlans (min + 1) max else []

let vid = 0xaa

let config_switch sw = 
	let send = Sw.send sw 0l in
  let actions = push_vlan vid @ [Output AllPorts] in
  lwt _ = send (FlowModMsg delete_all_flows) in
  lwt _ = send (FlowModMsg (add_flow 400 [] [ApplyActions actions])) in
  lwt _ = send (FlowModMsg (add_flow 500 [match_vlan vid] [ApplyActions [PopVlan; Output AllPorts]])) in

	Format.eprintf "Configured switch %Lx.\n%!" (Sw.id sw);
	Lwt.return ()

let main () =
	Lwt_main.run
  (Format.eprintf "Running OpenFlow 1.3 VLAN stack demo...\n%!";
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

