open Core.Std

module Platform = Async_OpenFlow_Platform
module Header = OpenFlow_Header
module M = OpenFlow0x04.Message

module Message : Platform.Message with type t = (Header.xid * M.t) = struct

  type t = (Header.xid * M.t) sexp_opaque with sexp

  let header_of (xid, m)= M.header_of xid m
  let parse hdr buf = M.parse hdr (Cstruct.to_string buf)

  let marshal (xid, m) buf =
    let str = M.marshal xid m in
    let len = String.length str in
    Cstruct.blit_from_string str 0 buf 0 len;
    len

  let to_string _ = "we do not have an implementation of to_string for 1.3"

end