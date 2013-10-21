include SDN_Types.SWITCH

val initialize : Lwt_unix.file_descr -> t option Lwt.t

val recv_hello_from_switch : Lwt_unix.file_descr -> int option Lwt.t
