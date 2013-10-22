let () = match Array.to_list Sys.argv with
  | [ _; "fast-failover" ] -> FastFailover.main ()
  | [ _; "set-mask" ] -> SetMask.main ()
  | [ _; "vlan-stacks" ] -> VlanStacks.main ()
  | _ -> Format.printf "Invalid arguments.\n"