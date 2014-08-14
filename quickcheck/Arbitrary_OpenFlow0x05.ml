open OpenFlow0x05
open OpenFlow0x05_Core
open Arbitrary_Base

open QuickCheck
module Gen = QuickCheck_gen

let sum (lst : int list) = List.fold_left (fun x y -> x + y) 0 lst

let arbitrary_32mask =
  let open Gen in
  (choose_int (1, 32)) >>= fun a ->
    ret_gen (Int32.of_int a)

let arbitrary_128mask =
  let open Gen in
  (choose_int (1,64)) >>= fun a ->
  (choose_int (0,64)) >>= fun b ->
    ret_gen (Int64.of_int b,Int64.of_int a)

let arbitrary_64mask = 
  let open Gen in
  (choose_int (1,64)) >>= fun a ->
    ret_gen (Int64.of_int a)

let arbitrary_48mask =
  let open Gen in
  (choose_int (1,48)) >>= fun a ->
    ret_gen (Int64.of_int a)

let arbitrary_12mask =
  let open Gen in
  (choose_int (1,12)) >>= fun a ->
    ret_gen a

let arbitrary_16mask =
  let open Gen in
  (choose_int (1,16)) >>= fun a ->
    ret_gen a
    
let arbitrary_masked arb arb_mask =
  let open OpenFlow0x05_Core in
  let open Gen in
  frequency [
    (1, arb >>= fun v -> ret_gen {OpenFlow0x05_Core.m_value = v; m_mask = None});
    (3, arb >>= fun v ->
        arb_mask >>= fun m -> ret_gen {OpenFlow0x05_Core.m_value = v; m_mask = Some m}) ]

let arbitrary_timeout =
    let open OpenFlow0x05_Core in
    let open Gen in
    oneof [
        ret_gen Permanent;
        arbitrary_uint16 >>= (fun n -> ret_gen (ExpiresAfter n))
    ]

let fill_with_0 n= 
    String.make n '\000'

let arbitrary_stringl n=
    let open Gen in
    (choose_int (0,n)) >>= fun a ->
    arbitrary_stringN a >>= fun str ->
    ret_gen  (str ^ (fill_with_0 (n-a)))

module type OpenFlow0x05_Arbitrary = sig

    type t
    type s

    val arbitrary : t arbitrary

    val to_string : t -> string

    val parse : s -> t
    val marshal : t -> s

end

module type OpenFlow0x05_ArbitraryCstruct = sig
  type t

  val arbitrary : t arbitrary

  val to_string : t -> string

  val parse : Cstruct.t -> t
  val marshal : Cstruct.t -> t -> int

  val size_of : t -> int

end

module OpenFlow0x05_Unsize(ArbC : OpenFlow0x05_ArbitraryCstruct) = struct
  type t = ArbC.t
  type s = Cstruct.t

  let arbitrary = ArbC.arbitrary

  let to_string = ArbC.to_string

  let parse = ArbC.parse

  let marshal m =
    let bytes = Cstruct.of_bigarray Bigarray.(Array1.create char c_layout (ArbC.size_of m))
      in ignore (ArbC.marshal bytes m); bytes
end

module Experimenter = struct
  open Gen
  type t = Experimenter.t

  let arbitrary = 
    let open Gen in 
    let open Experimenter in 
    arbitrary_uint32 >>= fun experimenter ->
    arbitrary_uint32 >>= fun exp_typ -> 
    ret_gen { experimenter; exp_typ }

  let marshal = Experimenter.marshal
  let parse = Experimenter.parse
  let to_string = Experimenter.to_string
  let size_of = Experimenter.sizeof

end

module PortDesc = struct

  module Properties = struct
    module EthFeatures = struct
      type t = PortDesc.Properties.EthFeatures.t
      type s = Int32.t
      
      let arbitrary = 
        let open Gen in
        let open PortDesc.Properties.EthFeatures in
        arbitrary_bool >>= fun rate_10mb_hd ->
        arbitrary_bool >>= fun rate_10mb_fd ->
        arbitrary_bool >>= fun rate_100mb_hd ->
        arbitrary_bool >>= fun rate_100mb_fd ->
        arbitrary_bool >>= fun rate_1gb_hd ->
        arbitrary_bool >>= fun rate_1gb_fd ->
        arbitrary_bool >>= fun rate_10gb_fd ->
        arbitrary_bool >>= fun rate_40gb_fd ->
        arbitrary_bool >>= fun rate_100gb_fd ->
        arbitrary_bool >>= fun rate_1tb_fd ->
        arbitrary_bool >>= fun other ->
        arbitrary_bool >>= fun copper ->
        arbitrary_bool >>= fun fiber ->
        arbitrary_bool >>= fun autoneg ->
        arbitrary_bool >>= fun pause ->
        arbitrary_bool >>= fun pause_asym ->
        ret_gen {
          rate_10mb_hd; rate_10mb_fd; 
          rate_100mb_hd; rate_100mb_fd;
          rate_1gb_hd; rate_1gb_fd;
          rate_10gb_fd; rate_40gb_fd;
          rate_100gb_fd; rate_1tb_fd;
          other; copper; fiber;
          autoneg; pause; pause_asym
        }

      let to_string = PortDesc.Properties.EthFeatures.to_string
      let marshal = PortDesc.Properties.EthFeatures.marshal
      let parse = PortDesc.Properties.EthFeatures.parse
    end

    module OptFeatures = struct
      type t = PortDesc.Properties.OptFeatures.t
      type s = Int32.t
      
      let arbitrary = 
        let open Gen in
        let open PortDesc.Properties.OptFeatures in
        arbitrary_bool >>= fun rx_tune ->
        arbitrary_bool >>= fun tx_tune ->
        arbitrary_bool >>= fun tx_pwr ->
        arbitrary_bool >>= fun use_freq ->
        ret_gen {
            rx_tune; tx_tune; 
            tx_pwr; use_freq
        }

      let to_string = PortDesc.Properties.OptFeatures.to_string
      let marshal = PortDesc.Properties.OptFeatures.marshal
      let parse = PortDesc.Properties.OptFeatures.parse
    end

    type t = PortDesc.Properties.t

    let arbitrary = 
      let open Gen in
      oneof [
        (EthFeatures.arbitrary >>= fun curr ->
         EthFeatures.arbitrary >>= fun advertised ->
         EthFeatures.arbitrary >>= fun supported ->
         EthFeatures.arbitrary >>= fun peer ->
         arbitrary_uint32 >>= fun curr_speed ->
         arbitrary_uint32 >>= fun max_speed ->
         ret_gen (PropEthernet { curr; advertised; supported; peer; curr_speed; max_speed } ));
        (OptFeatures.arbitrary >>= fun supported ->
         arbitrary_uint32 >>= fun tx_min_freq_lmda ->
         arbitrary_uint32 >>= fun tx_max_freq_lmda ->
         arbitrary_uint32 >>= fun tx_grid_freq_lmda ->
         arbitrary_uint32 >>= fun rx_min_freq_lmda ->
         arbitrary_uint32 >>= fun rx_max_freq_lmda ->
         arbitrary_uint32 >>= fun rx_grid_freq_lmda ->
         arbitrary_uint16 >>= fun tx_pwr_min ->
         arbitrary_uint16 >>= fun tx_pwr_max ->
         ret_gen (PropOptical {supported; tx_min_freq_lmda; tx_max_freq_lmda; tx_grid_freq_lmda;
                               rx_min_freq_lmda; rx_max_freq_lmda; rx_grid_freq_lmda;
                               tx_pwr_min; tx_pwr_max} ));
        (Experimenter.arbitrary >>= fun experimenter ->
         ret_gen (PropExp experimenter))
      ]


    let to_string = PortDesc.Properties.to_string
    let marshal = PortDesc.Properties.marshal
    let parse = PortDesc.Properties.parse
    let size_of = PortDesc.Properties.sizeof
  end

  module State = struct
    type t = PortDesc.State.t
    type s = Int32.t
    let arbitrary =
        let open Gen in
        let open PortDesc.State in
        arbitrary_bool >>= fun link_down ->
        arbitrary_bool >>= fun blocked ->
        arbitrary_bool >>= fun live ->
        ret_gen {
            link_down;
            blocked;
            live
        }
    let to_string = PortDesc.State.to_string
    let marshal = PortDesc.State.marshal
    let parse = PortDesc.State.parse
  end

  module Config = struct
    type t = PortDesc.Config.t
    type s = Int32.t
    let arbitrary =
        let open Gen in
        let open PortDesc.Config in
        arbitrary_bool >>= fun port_down ->
        arbitrary_bool >>= fun no_recv ->
        arbitrary_bool >>= fun no_fwd ->
        arbitrary_bool >>= fun no_packet_in ->
        ret_gen {
            port_down;
            no_recv;
            no_fwd;
            no_packet_in
        }
    let to_string = PortDesc.Config.to_string
    let marshal = PortDesc.Config.marshal
    let parse = PortDesc.Config.parse
  end
  
  type t = PortDesc.t
  
  let arbitrary =
    let open Gen in
    arbitrary_uint32 >>= fun port_no ->
    arbitrary_uint48 >>= fun hw_addr ->
    arbitrary_stringN 16 >>= fun name ->
    Config.arbitrary >>= fun config ->
    State.arbitrary >>= fun state ->
    list1 Properties.arbitrary >>= fun properties ->
    ret_gen {
        port_no;
        hw_addr;
        name;
        config;
        state;
        properties
    }
  
  let to_string = PortDesc.to_string
  let parse = PortDesc.parse
  let marshal = PortDesc.marshal
  let size_of = PortDesc.sizeof

end


module OfpMatch = struct
    open Gen
    type t = OfpMatch.t

    module Oxm = struct
        type t = Oxm.t
        
        let arbitrary = 
            let open Gen in
            let open Oxm in
            let arbitrary_dscp = 
              (choose_int (0,64)) >>= fun a ->
              ret_gen a in
            let arbitrary_ecn = 
            (choose_int (0,3)) >>= fun a ->
              ret_gen a in
            let arbitrary_24mask =
              let open Gen in
              (choose_int (1,24)) >>= fun a ->
                ret_gen (Int32.of_int a) in
            let arbitrary_uint24 =
              arbitrary_uint16 >>= fun a ->
              arbitrary_uint8 >>= fun b ->
                let open Int32 in
                let hi = shift_left (of_int a) 8 in
                let lo = of_int b in
                ret_gen (logor hi lo) in
            let arbitrary_ipv6hdr =
              arbitrary_bool >>= fun noext ->
              arbitrary_bool >>= fun esp ->
              arbitrary_bool >>= fun auth ->
              arbitrary_bool >>= fun dest ->
              arbitrary_bool >>= fun frac ->
              arbitrary_bool >>= fun router ->
              arbitrary_bool >>= fun hop ->
              arbitrary_bool >>= fun unrep ->
              arbitrary_bool >>= fun unseq ->
              ret_gen {noext; esp; auth; dest; frac; router; hop; unrep; unseq } in
            arbitrary_uint32 >>= fun portId ->
            arbitrary_uint32 >>= fun portPhyId ->
            arbitrary_masked arbitrary_uint64 arbitrary_64mask >>= fun oxmMetadata ->
            arbitrary_uint16 >>= fun oxmEthType ->
            arbitrary_masked arbitrary_uint48 arbitrary_48mask >>= fun oxmEthDst ->
            arbitrary_masked arbitrary_uint48 arbitrary_48mask >>= fun oxmEthSrc ->
            arbitrary_masked arbitrary_uint12 arbitrary_12mask >>= fun oxmVlanVId ->
            arbitrary_uint8 >>= fun oxmVlanPcp ->
            arbitrary_uint8 >>= fun oxmIPProto ->
            arbitrary_dscp >>= fun oxmIPDscp ->
            arbitrary_ecn >>= fun oxmIPEcn ->
            arbitrary_masked arbitrary_uint32 arbitrary_32mask >>= fun oxmIP4Src ->
            arbitrary_masked arbitrary_uint32 arbitrary_32mask >>= fun oxmIP4Dst ->
            arbitrary_uint16 >>= fun oxmTCPSrc ->
            arbitrary_uint16 >>= fun oxmTCPDst ->
            arbitrary_uint16 >>= fun oxmARPOp ->
            arbitrary_masked arbitrary_uint32 arbitrary_32mask >>= fun oxmARPSpa ->
            arbitrary_masked arbitrary_uint32 arbitrary_32mask >>= fun oxmARPTpa ->
            arbitrary_masked arbitrary_uint48 arbitrary_48mask >>= fun oxmARPSha ->
            arbitrary_masked arbitrary_uint48 arbitrary_48mask >>= fun oxmARPTha ->
            arbitrary_uint8 >>= fun oxmICMPType ->
            arbitrary_uint8 >>= fun oxmICMPCode ->
            arbitrary_uint32 >>= fun oxmMPLSLabel ->
            arbitrary_uint8 >>= fun oxmMPLSTc ->
            arbitrary_masked arbitrary_uint64 arbitrary_64mask >>= fun oxmTunnelId ->
            arbitrary_masked arbitrary_uint128 arbitrary_128mask >>= fun oxmIPv6Src ->
            arbitrary_masked arbitrary_uint128 arbitrary_128mask >>= fun oxmIPv6Dst ->
            arbitrary_masked arbitrary_uint32 arbitrary_32mask  >>= fun oxmIPv6FLabel ->
            arbitrary_masked arbitrary_uint128 arbitrary_128mask >>= fun oxmIPv6NDTarget ->
            arbitrary_masked arbitrary_uint24 arbitrary_24mask >>= fun oxmPBBIsid ->
            arbitrary_masked arbitrary_ipv6hdr arbitrary_ipv6hdr  >>= fun oxmIPv6ExtHdr ->
            arbitrary_bool >>= fun oxmMPLSBos ->
            arbitrary_uint16 >>= fun oxmUDPSrc ->
            arbitrary_uint16 >>= fun oxmUDPDst ->
            arbitrary_uint16 >>= fun oxmSCTPSrc ->
            arbitrary_uint16 >>= fun oxmSCTPDst ->
            arbitrary_uint8 >>= fun oxmICMPv6Type ->
            arbitrary_uint8 >>= fun oxmICMPv6Code ->
            arbitrary_uint48 >>= fun oxmIPv6NDSll ->
            arbitrary_uint48 >>= fun oxmIPv6NDTll ->
            arbitrary_bool >>= fun oxmPBBUCA ->
            oneof [
                ret_gen (OxmInPort portId);
                ret_gen (OxmInPhyPort portPhyId);
                ret_gen (OxmMetadata oxmMetadata);
                ret_gen (OxmEthType oxmEthType);
                ret_gen (OxmEthDst oxmEthDst);
                ret_gen (OxmEthSrc oxmEthSrc);
                ret_gen (OxmVlanVId oxmVlanVId);
                ret_gen (OxmVlanPcp oxmVlanPcp);
                ret_gen (OxmIPProto oxmIPProto);
                ret_gen (OxmIPDscp oxmIPDscp);
                ret_gen (OxmIPEcn oxmIPEcn);
                ret_gen (OxmIP4Src oxmIP4Src);
                ret_gen (OxmIP4Dst oxmIP4Dst);
                ret_gen (OxmTCPSrc oxmTCPSrc);
                ret_gen (OxmTCPDst oxmTCPDst);
                ret_gen (OxmARPOp oxmARPOp);
                ret_gen (OxmARPSpa oxmARPSpa);
                ret_gen (OxmARPTpa oxmARPTpa);
                ret_gen (OxmARPSha oxmARPSha);
                ret_gen (OxmARPTha oxmARPTha);
                ret_gen (OxmICMPType oxmICMPType);
                ret_gen (OxmICMPCode oxmICMPCode);
                ret_gen (OxmMPLSLabel oxmMPLSLabel);
                ret_gen (OxmMPLSTc oxmMPLSTc);
                ret_gen (OxmTunnelId oxmTunnelId);
                ret_gen (OxmUDPSrc oxmUDPSrc);
                ret_gen (OxmUDPDst oxmUDPDst);
                ret_gen (OxmSCTPSrc oxmSCTPSrc);
                ret_gen (OxmSCTPDst oxmSCTPDst);
                ret_gen (OxmIPv6Src oxmIPv6Src);
                ret_gen (OxmIPv6Dst oxmIPv6Dst);
                ret_gen (OxmIPv6FLabel oxmIPv6FLabel);
                ret_gen (OxmICMPv6Type oxmICMPv6Type);
                ret_gen (OxmICMPv6Code oxmICMPv6Code);
                ret_gen (OxmIPv6NDTarget oxmIPv6NDTarget);
                ret_gen (OxmIPv6NDSll oxmIPv6NDSll);
                ret_gen (OxmIPv6NDTll oxmIPv6NDTll);
                ret_gen (OxmMPLSBos oxmMPLSBos);
                ret_gen (OxmPBBIsid oxmPBBIsid);
                ret_gen (OxmIPv6ExtHdr oxmIPv6ExtHdr);
                ret_gen (OxmPBBUCA oxmPBBUCA)
            ]
        let marshal = Oxm.marshal
        let to_string = Oxm.to_string
        let size_of = Oxm.sizeof
        let parse bits = 
            let p,_ = Oxm.parse bits in
            p
    end

    module OxmHeader = struct
        type t = Oxm.t
        
        module Oxm = OpenFlow0x05.Oxm
        
        let arbitrary = 
            let open Gen in
            let open Oxm in
            let ipv6hdr_nul = {noext = false; esp = false; auth = false; dest = false; frac = false; router = false; hop = false; unrep = false; unseq = false } in
            arbitrary_masked (ret_gen 0L) (ret_gen 0L) >>= fun oxmMetadata ->
            arbitrary_masked (ret_gen 0L) (ret_gen 0L) >>= fun oxmEthDst ->
            arbitrary_masked (ret_gen 0L) (ret_gen 0L) >>= fun oxmEthSrc ->
            arbitrary_masked (ret_gen 0) (ret_gen 0) >>= fun oxmVlanVId ->
            arbitrary_masked (ret_gen 0l) (ret_gen 0l) >>= fun oxmIP4Src ->
            arbitrary_masked (ret_gen 0l) (ret_gen 0l) >>= fun oxmIP4Dst ->
            arbitrary_masked (ret_gen 0l) (ret_gen 0l) >>= fun oxmARPSpa ->
            arbitrary_masked (ret_gen 0l) (ret_gen 0l) >>= fun oxmARPTpa ->
            arbitrary_masked (ret_gen 0L) (ret_gen 0L) >>= fun oxmARPSha ->
            arbitrary_masked (ret_gen 0L) (ret_gen 0L) >>= fun oxmARPTha ->
            arbitrary_masked (ret_gen 0L) (ret_gen 0L) >>= fun oxmTunnelId ->
            arbitrary_masked (ret_gen (0L,0L)) (ret_gen (0L,0L)) >>= fun oxmIPv6Src ->
            arbitrary_masked (ret_gen (0L,0L)) (ret_gen (0L,0L)) >>= fun oxmIPv6Dst ->
            arbitrary_masked (ret_gen 0l) (ret_gen 0l) >>= fun oxmIPv6FLabel ->
            arbitrary_masked (ret_gen (0L,0L)) (ret_gen (0L,0L)) >>= fun oxmIPv6NDTarget ->
            arbitrary_masked (ret_gen 0l) (ret_gen 0l) >>= fun oxmPBBIsid ->
            arbitrary_masked (ret_gen ipv6hdr_nul) (ret_gen ipv6hdr_nul) >>= fun oxmIPv6ExtHdr ->
            
            oneof [
                ret_gen (OxmInPort 0l);
                ret_gen (OxmInPhyPort 0l);
                ret_gen (OxmMetadata oxmMetadata);
                ret_gen (OxmEthType 0);
                ret_gen (OxmEthDst oxmEthDst);
                ret_gen (OxmEthSrc oxmEthSrc);
                ret_gen (OxmVlanVId oxmVlanVId);
                ret_gen (OxmVlanPcp 0);
                ret_gen (OxmIPProto 0);
                ret_gen (OxmIPDscp 0);
                ret_gen (OxmIPEcn 0);
                ret_gen (OxmIP4Src oxmIP4Src);
                ret_gen (OxmIP4Dst oxmIP4Dst);
                ret_gen (OxmTCPSrc 0);
                ret_gen (OxmTCPDst 0);
                ret_gen (OxmARPOp 0);
                ret_gen (OxmARPSpa oxmARPSpa);
                ret_gen (OxmARPTpa oxmARPTpa);
                ret_gen (OxmARPSha oxmARPSha);
                ret_gen (OxmARPTha oxmARPTha);
                ret_gen (OxmICMPType 0);
                ret_gen (OxmICMPCode 0);
                ret_gen (OxmMPLSLabel 0l);
                ret_gen (OxmMPLSTc 0);
                ret_gen (OxmTunnelId oxmTunnelId);
                ret_gen (OxmUDPSrc 0);
                ret_gen (OxmUDPDst 0);
                ret_gen (OxmSCTPSrc 0);
                ret_gen (OxmSCTPDst 0);
                ret_gen (OxmIPv6Src oxmIPv6Src);
                ret_gen (OxmIPv6Dst oxmIPv6Dst);
                ret_gen (OxmIPv6FLabel oxmIPv6FLabel);
                ret_gen (OxmICMPv6Type 0);
                ret_gen (OxmICMPv6Code 0);
                ret_gen (OxmIPv6NDTarget oxmIPv6NDTarget);
                ret_gen (OxmIPv6NDSll 0L);
                ret_gen (OxmIPv6NDTll 0L);
                ret_gen (OxmMPLSBos false);
                ret_gen (OxmPBBIsid oxmPBBIsid);
                ret_gen (OxmIPv6ExtHdr oxmIPv6ExtHdr);
                ret_gen (OxmPBBUCA false)
            ]

        let marshal = Oxm.marshal_header

        let to_string = Oxm.field_name
        let size_of = Oxm.sizeof
        let parse bits = 
            let p,_ = Oxm.parse_header bits in
            p
    end

    let arbitrary =
        let open Gen in
        let open OfpMatch in
        arbitrary_list Oxm.arbitrary >>= fun ofpMatch ->
        ret_gen ofpMatch
    
    let marshal = OfpMatch.marshal
    let parse bits= 
        let ofpMatch,_ = OfpMatch.parse bits in
        ofpMatch
    let to_string = OfpMatch.to_string
    let size_of = OfpMatch.sizeof
end

module PseudoPort = Arbitrary_OpenFlow0x04.PseudoPort

module Action = Arbitrary_OpenFlow0x04.Action

module Instructions = Arbitrary_OpenFlow0x04.Instructions

module SwitchFeatures = struct
  open Gen
  type t = SwitchFeatures.t

  let arbitrary = 
    let open Gen in
    let arbitrary_capabilities = 
      let open OpenFlow0x04_Core in
      arbitrary_bool >>= fun flow_stats ->
      arbitrary_bool >>= fun table_stats ->
      arbitrary_bool >>= fun port_stats ->
      arbitrary_bool >>= fun group_stats ->
      arbitrary_bool >>= fun ip_reasm ->
      arbitrary_bool >>= fun queue_stats ->
      arbitrary_bool >>= fun port_blocked ->
      ret_gen {flow_stats; table_stats; port_stats; group_stats; ip_reasm; queue_stats; port_blocked } in
    arbitrary_capabilities >>= fun supported_capabilities ->
    arbitrary_uint64 >>= fun datapath_id ->
    arbitrary_uint32 >>= fun num_buffers ->
    arbitrary_uint8 >>= fun num_tables ->
    arbitrary_uint8 >>= fun aux_id ->
    ret_gen { datapath_id; num_buffers; num_tables; aux_id; supported_capabilities }

  let marshal = SwitchFeatures.marshal
  let parse = SwitchFeatures.parse
  let to_string = SwitchFeatures.to_string
  let size_of = SwitchFeatures.sizeof
end

module SwitchConfig = Arbitrary_OpenFlow0x04.SwitchConfig

module TableMod = struct
  open Gen
  open OpenFlow0x05_Core

  module Properties = struct
    open Gen
    open OpenFlow0x05_Core

    type t = TableMod.Properties.t

    let arbitrary_eviction =
      arbitrary_bool >>= fun other ->
      arbitrary_bool >>= fun importance ->
      arbitrary_bool >>= fun lifetime ->
      ret_gen { other; importance; lifetime }

    let arbitrary_vacancy =
      arbitrary_uint8 >>= fun vacancy_down ->
      arbitrary_uint8 >>= fun vacancy_up ->
      arbitrary_uint8 >>= fun vacancy ->
      ret_gen { vacancy_down; vacancy_up; vacancy }

    let arbitrary = 
      arbitrary_eviction >>= fun e ->
      arbitrary_vacancy >>= fun v ->
      oneof [
         ret_gen (Eviction e);
         ret_gen (Vacancy v)
      ]

    let marshal = TableMod.Properties.marshal
    let parse = TableMod.Properties.parse
    let to_string = TableMod.Properties.to_string
    let size_of = TableMod.Properties.sizeof
  end
  type t = TableMod.t

  let arbitrary_config =
    arbitrary_bool >>= fun eviction ->
    arbitrary_bool >>= fun vacancyEvent ->
    ret_gen { eviction; vacancyEvent }

  let arbitrary = 
    arbitrary_uint8 >>= fun table_id ->
    arbitrary_config >>= fun config ->
    arbitrary_list Properties.arbitrary >>= fun properties ->
    ret_gen { table_id; config ; properties }

  let marshal = TableMod.marshal
  let parse = TableMod.parse
  let to_string = TableMod.to_string
  let size_of = TableMod.sizeof

end

module FlowMod = struct
    open Gen
    module FlowModCommand = struct
        type t = FlowMod.FlowModCommand.t

        let arbitrary =
            let open Gen in
            oneof [
                        ret_gen AddFlow;
                        ret_gen ModFlow;
                        ret_gen ModStrictFlow;
                        ret_gen DeleteFlow;
                        ret_gen DeleteStrictFlow;
                    ]
        let to_string = FlowMod.FlowModCommand.to_string
        let marshal = FlowMod.FlowModCommand.marshal
        let parse = FlowMod.FlowModCommand.parse
    end
    type t = FlowMod.t

    let arbitrary_flags =
        arbitrary_bool >>= fun fmf_send_flow_rem ->
        arbitrary_bool >>= fun fmf_check_overlap ->
        arbitrary_bool >>= fun fmf_reset_counts ->
        arbitrary_bool >>= fun fmf_no_pkt_counts ->
        arbitrary_bool >>= fun fmf_no_byt_counts ->
        ret_gen {
            fmf_send_flow_rem;
            fmf_check_overlap;
            fmf_reset_counts;
            fmf_no_pkt_counts;
            fmf_no_byt_counts
        }

    let arbitrary_buffer_id = 
        arbitrary_uint32 >>= fun bid ->
        oneof [
            ret_gen None;
            ret_gen (Some bid)
        ]

    let arbitrary = 
        arbitrary_masked arbitrary_uint64 arbitrary_64mask >>= fun mfCookie ->
        arbitrary_uint8 >>= fun mfTable_id ->
        arbitrary_timeout >>= fun mfIdle_timeout ->
        arbitrary_timeout >>= fun mfHard_timeout ->
        arbitrary_uint16 >>= fun mfPriority ->
        arbitrary_flags >>= fun mfFlags ->
        arbitrary_buffer_id >>= fun mfBuffer_id ->
        FlowModCommand.arbitrary >>= fun mfCommand ->
        PseudoPort.arbitrary_nc >>= fun mfPort ->
        oneof [ ret_gen None; ret_gen (Some mfPort)] >>= fun mfOut_port ->
        arbitrary_uint32 >>= fun mfGroup ->
        oneof [ ret_gen None; ret_gen (Some mfGroup)] >>= fun mfOut_group ->
        arbitrary_uint16 >>= fun mfImportance ->
        OfpMatch.arbitrary >>= fun mfOfp_match ->
        Instructions.arbitrary >>= fun mfInstructions ->
        ret_gen {
            mfCookie; mfTable_id;
            mfCommand; mfIdle_timeout;
            mfHard_timeout; mfPriority;
            mfBuffer_id;
            mfOut_port;
            mfOut_group; mfFlags; mfImportance;
            mfOfp_match; mfInstructions}
        
    let marshal = FlowMod.marshal
    let parse = FlowMod.parse
    let to_string = FlowMod.to_string
    let size_of = FlowMod.sizeof
end    

module Bucket = Arbitrary_OpenFlow0x04.Bucket

module GroupMod = Arbitrary_OpenFlow0x04.GroupMod

module PortMod = struct
  open Gen

  module Properties = struct
    open Gen
    type t = portModPropt

    let arbitrary = 
      oneof [
        (PortDesc.State.arbitrary >>= fun a ->
         ret_gen (PortModPropEthernet a));
        (PortDesc.Properties.OptFeatures.arbitrary >>= fun configure ->
         arbitrary_uint32 >>= fun freq_lmda ->
         arbitrary_uint32 >>= fun fl_offset ->
         arbitrary_uint32 >>= fun grid_span ->
         arbitrary_uint32 >>= fun tx_pwr ->
        ret_gen (PortModPropOptical {configure; freq_lmda; fl_offset; grid_span; tx_pwr}))
      ]
  
    let to_string = PortMod.Properties.to_string
    let marshal = PortMod.Properties.marshal
    let parse = PortMod.Properties.parse
    let size_of = PortMod.Properties.sizeof
  end

  type t = PortMod.t

  let arbitrary = 
    arbitrary_uint32 >>= fun mpPortNo ->
    arbitrary_uint48 >>= fun mpHw_addr ->
    PortDesc.Config.arbitrary >>= fun mpConfig ->
    PortDesc.Config.arbitrary >>= fun mpMask ->
    list1 Properties.arbitrary >>= fun mpProp ->
    ret_gen { mpPortNo; mpHw_addr; mpConfig; mpMask; mpProp}
  
  let marshal = PortMod.marshal
  let parse = PortMod.parse
  let to_string = PortMod.to_string
  let size_of = PortMod.sizeof

end

module FlowRemoved = struct

  open Gen

  type t = FlowRemoved.t

  let arbitrary_reason = 
    oneof [ 
      ret_gen FlowIdleTimeout;
      ret_gen FlowHardTiemout;
      ret_gen FlowDelete;
      ret_gen FlowGroupDelete;
      ret_gen FlowMeterDelete;
      ret_gen FlowEviction]

  let arbitrary =
    arbitrary_uint64 >>= fun cookie ->
    arbitrary_uint16 >>= fun priority ->
    arbitrary_reason >>= fun reason ->
    arbitrary_uint8 >>= fun table_id ->
    arbitrary_uint32 >>= fun duration_sec ->
    arbitrary_uint32 >>= fun duration_nsec ->
    arbitrary_timeout >>= fun idle_timeout ->
    arbitrary_timeout >>= fun hard_timeout ->
    arbitrary_uint64 >>= fun packet_count ->
    arbitrary_uint64 >>= fun byte_count ->
    OfpMatch.arbitrary >>= fun oxm ->
    ret_gen { cookie; priority; reason; table_id; duration_sec; duration_nsec;
              idle_timeout; hard_timeout; packet_count; byte_count; oxm }

  let marshal = FlowRemoved.marshal
  let parse = FlowRemoved.parse
  let to_string = FlowRemoved.to_string
  let size_of = FlowRemoved.sizeof

end

module QueueDescReq = struct
  open Gen

  type t = QueueDescReq.t

  let arbitrary = 
    PseudoPort.arbitrary_nc >>= fun port_no ->
    arbitrary_uint32 >>= fun queue_id ->
    ret_gen {port_no; queue_id}

  let marshal = QueueDescReq.marshal
  let parse = QueueDescReq.parse
  let to_string = QueueDescReq.to_string
  let size_of = QueueDescReq.sizeof

end

module FlowMonitorRequest = struct
  open Gen

  type t = FlowMonitorRequest.t

  let arbitrary_command = 
    oneof [
      ret_gen FMonAdd;
      ret_gen FMonModify;
      ret_gen FMonDelete]

  let arbitrary_flags = 
    arbitrary_bool >>= fun fmInitial ->
    arbitrary_bool >>= fun fmAdd ->
    arbitrary_bool >>= fun fmRemoved->
    arbitrary_bool >>= fun fmModify ->
    arbitrary_bool >>= fun fmInstructions ->
    arbitrary_bool >>= fun fmNoAbvrev ->
    arbitrary_bool >>= fun fmOnlyOwn ->
    ret_gen {fmInitial; fmAdd; fmRemoved; fmModify; fmInstructions; fmNoAbvrev; fmOnlyOwn}

  let arbitrary = 
    arbitrary_uint32 >>= fun fmMonitor_id ->
    PseudoPort.arbitrary_nc >>= fun fmOut_port ->
    arbitrary_uint32 >>= fun fmOut_group ->
    arbitrary_flags >>= fun fmFlags ->
    arbitrary_uint8 >>= fun fmTable_id ->
    arbitrary_command >>= fun fmCommand ->
    OfpMatch.arbitrary >>= fun fmMatch ->
    ret_gen { fmMonitor_id; fmOut_port; fmOut_group; fmFlags; fmTable_id; fmCommand; fmMatch}

  let marshal = FlowMonitorRequest.marshal
  let parse = FlowMonitorRequest.parse
  let to_string = FlowMonitorRequest.to_string
  let size_of = FlowMonitorRequest.sizeof

end

module MultipartReq = struct
  open Gen

  type t = MultipartReq.t

  let arbitrary_type = 
    oneof [
        ret_gen TableDescReq;
        QueueDescReq.arbitrary >>= (fun n -> ret_gen (QueueDescReq n));
        FlowMonitorRequest.arbitrary >>= (fun n -> ret_gen (FlowMonitorReq n));
    ]
  let arbitrary =
    arbitrary_bool >>= fun mpr_flags ->
    arbitrary_type >>= fun mpr_type ->
    ret_gen {
        mpr_type;
        mpr_flags
    }
  
  let marshal = MultipartReq.marshal
  let parse = MultipartReq.parse
  let to_string = MultipartReq.to_string
  let size_of = MultipartReq.sizeof

end
  
module PortStats = struct
  open Gen

  type t = PortStats.t

  module Properties = struct 
    module Ethernet = struct
      let arbitrary =
        arbitrary_uint64 >>= fun rx_frame_err ->
        arbitrary_uint64 >>= fun rx_over_err ->
        arbitrary_uint64 >>= fun rx_crc_err ->
        arbitrary_uint64 >>= fun collisions ->
        ret_gen {rx_frame_err; rx_over_err; rx_crc_err; collisions}
    end

    module Optical = struct
      let arbitrary_flags = 
        arbitrary_bool >>= fun rx_tune ->
        arbitrary_bool >>= fun tx_tune ->
        arbitrary_bool >>= fun tx_pwr ->
        arbitrary_bool >>= fun rx_pwr ->
        arbitrary_bool >>= fun tx_bias ->
        arbitrary_bool >>= fun tx_temp ->
        ret_gen {rx_tune; tx_tune; tx_pwr; rx_pwr; tx_bias; tx_temp}

      let arbitrary =
        arbitrary_flags >>= fun flags ->
        arbitrary_uint32 >>= fun tx_freq_lmda ->
        arbitrary_uint32 >>= fun tx_offset ->
        arbitrary_uint32 >>= fun tx_grid_span ->
        arbitrary_uint32 >>= fun rx_freq_lmda ->
        arbitrary_uint32 >>= fun rx_offset ->
        arbitrary_uint32 >>= fun rx_grid_span ->
        arbitrary_uint16 >>= fun tx_pwr ->
        arbitrary_uint16 >>= fun rx_pwr ->
        arbitrary_uint16 >>= fun bias_current ->
        arbitrary_uint16 >>= fun temperature ->
        ret_gen {flags; tx_freq_lmda; tx_offset; tx_grid_span; 
                 rx_freq_lmda; rx_offset; rx_grid_span; tx_pwr; 
                 rx_pwr; bias_current; temperature}
    end

    type t = PortStats.Properties.t

    let arbitrary = 
      oneof [
        (Ethernet.arbitrary >>= (fun n -> ret_gen (PortStatsPropEthernet n)));
        (Optical.arbitrary >>= (fun n -> ret_gen (PortStatsPropOptical n)));
        (Experimenter.arbitrary >>= (fun n -> ret_gen (PortStatsPropExperimenter n)))
      ]
      

    let marshal = PortStats.Properties.marshal
    let parse = PortStats.Properties.parse
    let to_string = PortStats.Properties.to_string
    let size_of = PortStats.Properties.sizeof

  end

  let arbitrary =
      arbitrary_uint32 >>= fun psPort_no ->
      arbitrary_uint64 >>= fun rx_packets ->
      arbitrary_uint64 >>= fun tx_packets ->
      arbitrary_uint64 >>= fun rx_bytes ->
      arbitrary_uint64 >>= fun tx_bytes ->
      arbitrary_uint64 >>= fun rx_dropped ->
      arbitrary_uint64 >>= fun tx_dropped ->
      arbitrary_uint64 >>= fun rx_errors ->
      arbitrary_uint64 >>= fun tx_errors ->
      arbitrary_uint32 >>= fun duration_sec ->
      arbitrary_uint32 >>= fun duration_nsec ->
      arbitrary_list Properties.arbitrary >>= fun properties ->
      ret_gen {
          psPort_no;
          duration_sec;
          duration_nsec;
          rx_packets;
          tx_packets;
          rx_bytes;
          tx_bytes;
          rx_dropped;
          tx_dropped;
          rx_errors;
          tx_errors;
          properties
      }

  let marshal = PortStats.marshal
  let parse = PortStats.parse
  let to_string = PortStats.to_string
  let size_of = PortStats.sizeof
end 

module QueueStats = struct
  open Gen

  module Properties = struct

    type t = QueueStats.Properties.t

    let arbitrary = 
      oneof [
        (Experimenter.arbitrary >>= (fun n -> ret_gen (ExperimenterQueueStats n)))
        ]
      

    let marshal = QueueStats.Properties.marshal
    let parse = QueueStats.Properties.parse
    let to_string = QueueStats.Properties.to_string
    let size_of = QueueStats.Properties.sizeof
  end

  type t = QueueStats.t

  let arbitrary = 
    arbitrary_uint32 >>= fun qsPort_no ->
    arbitrary_uint32 >>= fun queue_id ->
    arbitrary_uint64 >>= fun tx_bytes ->
    arbitrary_uint64 >>= fun tx_packets ->
    arbitrary_uint64 >>= fun tx_errors ->
    arbitrary_uint32 >>= fun duration_sec ->
    arbitrary_uint32 >>= fun duration_nsec ->
    arbitrary_list Properties.arbitrary >>= fun properties ->
    ret_gen { 
        qsPort_no;
        queue_id;
        tx_bytes;
        tx_packets;
        tx_errors;
        duration_sec;
        duration_nsec;
        properties
    }

  let marshal = QueueStats.marshal
  let parse = QueueStats.parse
  let to_string = QueueStats.to_string
  let size_of = QueueStats.sizeof

end

module TableDescReply = struct

  open Gen
  type t = TableDescReply.t

  let arbitrary =   
    arbitrary_uint8 >>= fun table_id ->
    TableMod.arbitrary_config >>= fun config ->
    arbitrary_list TableMod.Properties.arbitrary >>= fun properties ->
    ret_gen { table_id; config; properties }

  let marshal = TableDescReply.marshal
  let parse = TableDescReply.parse
  let to_string = TableDescReply.to_string
  let size_of = TableDescReply.sizeof

end

module QueueDescReply = struct
  open Gen

  module Properties = struct

    type t = QueueDescReply.Properties.t

    let arbitrary_rate = 
      frequency [
        (1, ret_gen Disabled);
        (10, choose_int (0,1000) >>= fun a ->
             ret_gen (Rate a))
      ]

    let arbitrary = 
      oneof [
        (arbitrary_rate >>= (fun n -> ret_gen (QueueDescPropMinRate n)));
        (arbitrary_rate >>= (fun n -> ret_gen (QueueDescPropMaxRate n)));
        (Experimenter.arbitrary >>= (fun n -> ret_gen (QueueDescPropExperimenter n)))
        ]
      

    let marshal = QueueDescReply.Properties.marshal
    let parse = QueueDescReply.Properties.parse
    let to_string = QueueDescReply.Properties.to_string
    let size_of = QueueDescReply.Properties.sizeof
  end

  type t = QueueDescReply.t

  let arbitrary = 
    arbitrary_uint32 >>= fun port_no ->
    arbitrary_uint32 >>= fun queue_id ->
    arbitrary_list Properties.arbitrary >>= fun properties ->
    ret_gen { port_no; queue_id; properties }

  let marshal = QueueDescReply.marshal
  let parse = QueueDescReply.parse
  let to_string = QueueDescReply.to_string
  let size_of = QueueDescReply.sizeof 
end

module FlowMonitorReply = struct

  open Gen
  type t = FlowMonitorReply.t

  module UpdateFull = struct
    let arbitrary event = 
      arbitrary_uint8 >>= fun table_id ->
      FlowRemoved.arbitrary_reason >>= fun reason ->
      arbitrary_timeout >>= fun idle_timeout ->
      arbitrary_timeout >>= fun hard_timeout ->
      arbitrary_uint16 >>= fun priority ->
      arbitrary_uint64 >>= fun cookie ->
      OfpMatch.arbitrary >>= fun updateMatch ->
      Instructions.arbitrary >>= fun instructions ->
      ret_gen { event; table_id; reason; idle_timeout; hard_timeout; priority; cookie; updateMatch; instructions }
  end

  let arbitrary = 
    oneof [
      (UpdateFull.arbitrary InitialUpdate >>= (fun n -> ret_gen (FmUpdateFull n)));
      (UpdateFull.arbitrary AddedUpdate >>= (fun n -> ret_gen (FmUpdateFull n)));
      (UpdateFull.arbitrary RemovedUpdate >>= (fun n -> ret_gen (FmUpdateFull n)));
      (UpdateFull.arbitrary ModifiedUpdate >>= (fun n -> ret_gen (FmUpdateFull n)));
      (arbitrary_uint32 >>= (fun n -> ret_gen (FmAbbrev n)));
      ret_gen (FmPaused Pause);
      ret_gen (FmPaused Resume)
    ]

  let marshal = FlowMonitorReply.marshal
  let parse = FlowMonitorReply.parse
  let to_string = FlowMonitorReply.to_string
  let size_of = FlowMonitorReply.sizeof 
end 

module MultipartReply = struct
  open Gen 
  type t = MultipartReply.t

  let arbitrary_type =
    arbitrary_bool >>= fun flags ->
    oneof [
      (arbitrary_list TableDescReply.arbitrary >>= (fun n -> ret_gen (TableDescReply n)));
      (arbitrary_list QueueDescReply.arbitrary >>= (fun n -> ret_gen (QueueDescReply n)));
      (arbitrary_list FlowMonitorReply.arbitrary >>= (fun n -> ret_gen (FlowMonitorReply n)))
      ]

  let arbitrary =
    arbitrary_bool >>= fun mpreply_flags ->
    arbitrary_type >>= fun mpreply_typ ->
    ret_gen {
        mpreply_typ;
        mpreply_flags
    }

  let marshal = MultipartReply.marshal
  let parse = MultipartReply.parse
  let to_string = MultipartReply.to_string
  let size_of = MultipartReply.sizeof
end

module BundleProp = struct

  open Gen
  type t = BundleProp.t

  let arbitrary = 
    oneof [
      (Experimenter.arbitrary >>= (fun n -> ret_gen (BundleExperimenter n)))
      ]    

  let marshal = BundleProp.marshal
  let parse = BundleProp.parse
  let to_string = BundleProp.to_string
  let size_of = BundleProp.sizeof

end

module BundleCtrl = struct

  open Gen
  type t = BundleCtrl.t

  let arbitrary_typ = 
    oneof [
      ret_gen OpenReq;
      ret_gen OpenReply;
      ret_gen CloseReq;
      ret_gen CloseReply;
      ret_gen CommitReq;
      ret_gen CommitReply;
      ret_gen DiscardReq;
      ret_gen DiscardReply
    ]

  let arbitrary_flags =
    arbitrary_bool >>= fun atomic ->
    arbitrary_bool >>= fun ordered ->
    ret_gen { atomic; ordered }

  let arbitrary =
    arbitrary_uint32 >>= fun bundle_id ->
    arbitrary_typ >>= fun typ ->
    arbitrary_flags >>= fun flags ->
    arbitrary_list BundleProp.arbitrary >>= fun properties ->
    ret_gen { bundle_id; typ; flags; properties }

  let marshal = BundleCtrl.marshal
  let parse = BundleCtrl.parse
  let to_string = BundleCtrl.to_string
  let size_of = BundleCtrl.sizeof

end
