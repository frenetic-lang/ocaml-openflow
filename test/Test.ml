(* This is a hack to set the name of the test library to "openflow" instead of
   "dummy", which is the default. Core ships with all its unit tests in the
   dummy library. So, if we link to core, then we first run the core test suite
   before we run ours (which takes time).

   The advertised way to set the library name is to send "-pa-ounit-lib libname" 
   as a flag to camlp4:

   https://github.com/janestreet/pa_ounit/blob/master/readme.md#building-and-running-the-tests-outside-of-jane-street

   But, this turns out to be hard/impossible to do with ocamlbuild:

   http://caml.inria.fr/mantis/view.php?id=6103

   The solution below works just fine. *)
let _ = 
  Pa_ounit_lib.Runtime.unset_lib "dummy";
  Pa_ounit_lib.Runtime.set_lib "openflow"

open OpenFlow0x01
open OpenFlow0x01_Stats
module Header = OpenFlow_Header

open QuickCheck

module Gen = QuickCheck_gen

module LatticeTest(L : sig
  type t
  val arbitrary_t : t arbitrary

  val match_all : t

  val less_eq : t -> t -> bool
  val eq : t -> t -> bool
  val join : t -> t -> t

  val string_of : t -> string
end) = struct

  let t_quickCheck prop =
    let test = testable_fun L.arbitrary_t L.string_of testable_bool in
    match quickCheck test prop with
      | Success -> true
      | Failure _ -> failwith "No failure expected"
      | Exhausted _ -> failwith "No exhaustion expected"

  let t2_quickCheck prop =
    let arb =
      let open Gen in
      L.arbitrary_t >>= fun p1 ->
      L.arbitrary_t >>= fun p2 ->
        ret_gen (p1, p2) in
    let show (p1, p2) =
      Printf.sprintf "%s, %s" (L.string_of p1) (L.string_of p2) in
    let test = testable_fun arb show testable_bool in
    match quickCheck test prop with
      | Success -> true
      | Failure _ -> failwith "No failure expected"
      | Exhausted _ -> failwith "No exhaustion expected"

  let t3_quickCheck prop =
    let arb =
      let open Gen in
      L.arbitrary_t >>= fun p1 ->
      L.arbitrary_t >>= fun p2 ->
      L.arbitrary_t >>= fun p3 ->
        ret_gen (p1, p2, p3) in
    let show (p1, p2, p3) =
      Printf.sprintf "%s, %s, %s"
        (L.string_of p1) (L.string_of p2) (L.string_of p3) in
    let test = testable_fun arb show testable_bool in
    match quickCheck test prop with
      | Success -> true
      | Failure _ -> failwith "No failure expected"
      | Exhausted _ -> failwith "No exhaustion expected"

  let implies a b = b || (not a)

  open L

  TEST "eq reflexive: eq p p" =
    let prop_eq_reflexive p =
      eq p p in
    t_quickCheck prop_eq_reflexive

  TEST "eq symmetric: eq p1 p2 <=> eq p2 p1" =
    let prop_eq_symmetric (p1, p2) =
      eq p1 p2 = eq p2 p1 in
    t2_quickCheck prop_eq_symmetric

  TEST "eq transitive: eq p1 p2 && eq p2 p3 => eq p1 p3" =
    let prop_eq_transitive (p1, p2, p3) =
      implies (eq p1 p2 && eq p2 p3) (eq p1 p3) in
    t3_quickCheck prop_eq_transitive

  TEST "less_eq reflexivity: less_eq p p" =
    let prop_reflexive p = less_eq p p = true in
    t_quickCheck prop_reflexive

  TEST "less_eq antisymmetry: less_eq p1 p2 && less_eq p2 p1 <=> p1 = p2" =
    let prop_antisymmetry (p1, p2) =
      (less_eq p1 p2 && less_eq p2 p1) = (eq p1 p2) in
    t2_quickCheck prop_antisymmetry

  TEST "less_eq transitivity: less_eq p1 p2 && less_eq p2 p3 => less_eq p1 p3" =
    let prop_transitivity (p1, p2, p3) =
      implies (less_eq p1 p2 && less_eq p2 p3) (less_eq p2 p3) in
    t3_quickCheck prop_transitivity

  TEST "less_eq top: less_eq p match_all" =
    let prop_top p =
      less_eq p match_all in
    t_quickCheck prop_top

  TEST "join symmetry: join p1 p2 <=> join p2 p1" =
    let prop_symmetry (p1, p2) = eq (join p1 p2) (join p2 p1) in
    t2_quickCheck prop_symmetry

  TEST "join exact: less_eq p1 (join p1 p2) && less_eq p2 (join p1 p2)" =
    let prop_exact (p1, p2) =
      less_eq p1 (join p1 p2) && less_eq p2 (join p1 p2) in
    t2_quickCheck prop_exact

  TEST "join least: less_eq p1 p3 && less_eq p2 p3 <=> less_eq (join p1 p2) p3" =
    let prop_least (p1, p2, p3) =
      (less_eq p1 p3 && less_eq p2 p3) = (less_eq (join p1 p2) p3) in
    t3_quickCheck prop_least

  TEST "join comparable least: less_eq p1 p2 <=> join p1 p2 = p2" =
    (* This is the same as "join least" when p2 = p3 *)
    let prop_comparable_least (p1, p2) =
      (less_eq p1 p2) = (eq (join p1 p2) p2) in
    t2_quickCheck prop_comparable_least
      
  TEST "eq partial: eq p1 p2 <=> less_eq p1 p2 && less_eq p2 p1" =
    let prop_eq_partial (p1, p2) =
      eq p1 p2 = (less_eq p1 p2 && less_eq p2 p1) in
    t2_quickCheck prop_eq_partial

end

module Ip = LatticeTest(struct
  include SDN_Types.Pattern.Ip
  let arbitrary_t = Arbitrary_SDN_Types.arbitrary_ip_mask
end)

module Pattern = LatticeTest(struct
  include SDN_Types.Pattern
  let arbitrary_t = Arbitrary_SDN_Types.arbitrary_pattern
end)

module RoundTripping = struct
  (* Test that `parse` is the left inverse of `marshal` *)
  let prop_roundtrip parse marshal e =
      parse (marshal e) = e

  (* Setup a quickCheck for a serlalizable OpenFlow datatype *)
  let openflow_quickCheck arbitrary show parse marshal =
      let test = testable_fun arbitrary show testable_bool in
      match quickCheck test (prop_roundtrip parse marshal) with
        | Success -> true
        | Failure _ -> failwith "No failure expected"
        | Exhausted _ -> failwith "No exhaustion expected"

  module Gen = Arbitrary_OpenFlow0x01
  module Gen0x04 = Arbitrary_OpenFlow0x04
  module Gen0x05 = Arbitrary_OpenFlow0x05

  TEST "OpenFlow_Header RoundTrip" =
    let module GenHeader = Gen.OpenFlow0x01_Unsize(Arbitrary_OpenFlow.Header) in
      (openflow_quickCheck GenHeader.arbitrary
          GenHeader.to_string GenHeader.parse GenHeader.marshal)

  TEST "OpenFlow0x01 Wildcards RoundTrip" =
      (openflow_quickCheck Gen.Wildcards.arbitrary
          Gen.Wildcards.to_string Gen.Wildcards.parse Gen.Wildcards.marshal)

  TEST "OpenFlow0x01 Match RoundTrip" =
      let module GenMatch = Gen.OpenFlow0x01_Unsize(Gen.Match) in
      (openflow_quickCheck GenMatch.arbitrary
          GenMatch.to_string GenMatch.parse GenMatch.marshal)

  TEST "OpenFlow0x01 PseudoPort RoundTrip" =
      (openflow_quickCheck Gen.PseudoPort.arbitrary
          Gen.PseudoPort.to_string Gen.PseudoPort.parse Gen.PseudoPort.marshal)

  TEST "OpenFlow0x01 Action RoundTrip" =
      let module GenAction = Gen.OpenFlow0x01_Unsize(Gen.Action) in
      (openflow_quickCheck GenAction.arbitrary
          GenAction.to_string GenAction.parse GenAction.marshal)

  TEST "OpenFlow0x01 Timeout RoundTrip" =
      let module GenTimeout = Gen.Timeout in
      (openflow_quickCheck GenTimeout.arbitrary
          GenTimeout.to_string GenTimeout.parse GenTimeout.marshal)

  TEST "OpenFlow0x01 FlowMod.Command RoundTrip" =
      let module GenCommand = Gen.FlowMod.Command in
      (openflow_quickCheck GenCommand.arbitrary
          GenCommand.to_string GenCommand.parse GenCommand.marshal)

  TEST "OpenFlow0x01 FlowMod RoundTrip" =
      let module GenFlowMod = Gen.OpenFlow0x01_Unsize(Gen.FlowMod) in
      (openflow_quickCheck GenFlowMod.arbitrary
          GenFlowMod.to_string GenFlowMod.parse GenFlowMod.marshal)

  TEST "OpenFlow0x01 FlowRemoved.Reason RoundTrip" =
      let module GenReason = Gen.FlowRemoved.Reason in
      (openflow_quickCheck GenReason.arbitrary
          GenReason.to_string GenReason.parse GenReason.marshal)

  TEST "OpenFlow0x01 FlowRemoved RoundTrip" =
      let module GenFlowRemoved = Gen.OpenFlow0x01_Unsize(Gen.FlowRemoved) in
      (openflow_quickCheck GenFlowRemoved.arbitrary
          GenFlowRemoved.to_string GenFlowRemoved.parse GenFlowRemoved.marshal)

  TEST "OpenFlow0x01 PortDescription.PortConfig RoundTrip" =
      let module GenPortConfig = Gen.PortDescription.PortConfig in
      (openflow_quickCheck GenPortConfig.arbitrary
          GenPortConfig.to_string GenPortConfig.parse GenPortConfig.marshal)

  TEST "OpenFlow0x01 PortDescription.PortState RoundTrip" =
      let module GenPortState = Gen.PortDescription.PortState in
      (openflow_quickCheck GenPortState.arbitrary
          GenPortState.to_string GenPortState.parse GenPortState.marshal)

  TEST "OpenFlow0x01 PortDescription RoundTrip" =
      let module GenPortDescription = Gen.OpenFlow0x01_Unsize(Gen.PortDescription) in
      (openflow_quickCheck GenPortDescription.arbitrary
          GenPortDescription.to_string GenPortDescription.parse GenPortDescription.marshal)

  TEST "OpenFlow0x01 PortStatus RoundTrip" =
      let module GenPortStatus = Gen.OpenFlow0x01_Unsize(Gen.PortStatus) in
      (openflow_quickCheck GenPortStatus.arbitrary
          GenPortStatus.to_string GenPortStatus.parse GenPortStatus.marshal)

  TEST "OpenFlow0x04 PortDesc.PortConfig RoundTrip" =
      let module GenPortConfig = Gen0x04.PortDesc.PortConfig in
      (openflow_quickCheck GenPortConfig.arbitrary
          GenPortConfig.to_string GenPortConfig.parse GenPortConfig.marshal)

  TEST "OpenFlow0x04 PortDesc.PortState RoundTrip" =
      let module GenPortState = Gen0x04.PortDesc.PortState in
      (openflow_quickCheck GenPortState.arbitrary
          GenPortState.to_string GenPortState.parse GenPortState.marshal)

  TEST "OpenFlow0x04 PortDesc.PortFeatures RoundTrip" =
      let module GenPortState = Gen0x04.PortDesc.PortState in
      (openflow_quickCheck GenPortState.arbitrary
          GenPortState.to_string GenPortState.parse GenPortState.marshal)

  TEST "OpenFlow0x04 PortDesc RoundTrip" =
      let module PortDesc = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.PortDesc) in
      (openflow_quickCheck PortDesc.arbitrary
          PortDesc.to_string PortDesc.parse PortDesc.marshal)

  TEST "OpenFlow0x04 PortStatus RoundTrip" =
      let module GenPortStatus = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.PortStatus) in
      (openflow_quickCheck GenPortStatus.arbitrary
          GenPortStatus.to_string GenPortStatus.parse GenPortStatus.marshal)

  TEST "OpenFlow0x04 PseudoPort RoundTrip" =
      let module GenPseudoPort = Gen0x04.PseudoPort in
      (openflow_quickCheck GenPseudoPort.arbitrary
          GenPseudoPort.to_string GenPseudoPort.parse GenPseudoPort.marshal)

  TEST "OpenFlow0x04 OfpMatch RoundTrip" =
      let module GenOfpMatch = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.OfpMatch) in
      (openflow_quickCheck GenOfpMatch.arbitrary
          GenOfpMatch.to_string GenOfpMatch.parse GenOfpMatch.marshal)

  TEST "OpenFlow0x04 OfpMatch.Oxm RoundTrip" =
      let module GenOxm = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.OfpMatch.Oxm) in
      (openflow_quickCheck GenOxm.arbitrary
          GenOxm.to_string GenOxm.parse GenOxm.marshal)
  
  TEST "OpenFlow0x04 OfpMatch.OxmHeader RoundTrip" =
      let module GenOxm = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.OfpMatch.OxmHeader) in
      (openflow_quickCheck GenOxm.arbitrary
          GenOxm.to_string GenOxm.parse GenOxm.marshal)

  TEST "OpenFlow0x04 Action RoundTrip" =
      let module GenAction = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.Action) in
      (openflow_quickCheck GenAction.arbitrary
          GenAction.to_string GenAction.parse GenAction.marshal)

  TEST "OpenFlow0x04 Instructions.Instruction RoundTrip" =
      let module GenInstruction = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.Instructions.Instruction) in
      (openflow_quickCheck GenInstruction.arbitrary
          GenInstruction.to_string GenInstruction.parse GenInstruction.marshal)

  TEST "OpenFlow0x04 Instructions RoundTrip" =
      let module GenInstructions = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.Instructions) in
      (openflow_quickCheck GenInstructions.arbitrary
          GenInstructions.to_string GenInstructions.parse GenInstructions.marshal)

  TEST "OpenFlow0x04 PortMod RoundTrip" =
      let module GenPortMod = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.PortMod) in
      (openflow_quickCheck GenPortMod.arbitrary
          GenPortMod.to_string GenPortMod.parse GenPortMod.marshal)

  TEST "OpenFlow0x04 MeterMod RoundTrip" =
      let module GenMeterMod = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MeterMod) in
      (openflow_quickCheck GenMeterMod.arbitrary
          GenMeterMod.to_string GenMeterMod.parse GenMeterMod.marshal)

  TEST "OpenFlow0x04 FlowMod RoundTrip" =
      let module GenFlowMod = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.FlowMod) in
      (openflow_quickCheck GenFlowMod.arbitrary
          GenFlowMod.to_string GenFlowMod.parse GenFlowMod.marshal)
  TEST "OpenFlow0x04 FlowMod.FlowModCommand RoundTrip" =
      let module GenFlowModCommand = Gen0x04.FlowMod.FlowModCommand in
      (openflow_quickCheck GenFlowModCommand.arbitrary
          GenFlowModCommand.to_string GenFlowModCommand.parse GenFlowModCommand.marshal)

  TEST "OpenFlow0x04 Bucket RoundTrip" =
      let module GenBucket = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.Bucket) in
      (openflow_quickCheck GenBucket.arbitrary
          GenBucket.to_string GenBucket.parse GenBucket.marshal)

  TEST "OpenFlow0x04 MultipartReq.TableFeatures.TableFeatureProp RoundTrip" =
      let module GenTableFeatureProp = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReq.TableFeatures.TableFeatureProp) in
      (openflow_quickCheck GenTableFeatureProp.arbitrary
          GenTableFeatureProp.to_string GenTableFeatureProp.parse GenTableFeatureProp.marshal)

  TEST "OpenFlow0x04 MultipartReq.TableFeatures.TableFeature RoundTrip" =
      let module GenTableFeature = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReq.TableFeatures.TableFeature) in
      (openflow_quickCheck GenTableFeature.arbitrary
          GenTableFeature.to_string GenTableFeature.parse GenTableFeature.marshal)

  TEST "OpenFlow0x04 MultipartReq.TableFeatures RoundTrip" =
      let module GenTableFeatureReq = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReq.TableFeatures) in
      (openflow_quickCheck GenTableFeatureReq.arbitrary
          GenTableFeatureReq.to_string GenTableFeatureReq.parse GenTableFeatureReq.marshal)

  TEST "OpenFlow0x04 MultipartReq.FlowRequest RoundTrip" =
      let module GenTableFlowReq = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReq.FlowRequest) in
      (openflow_quickCheck GenTableFlowReq.arbitrary
          GenTableFlowReq.to_string GenTableFlowReq.parse GenTableFlowReq.marshal)

  TEST "OpenFlow0x04 MultipartReq.QueueRequest RoundTrip" =
      let module GenTableQueueReq = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReq.QueueRequest) in
      (openflow_quickCheck GenTableQueueReq.arbitrary
          GenTableQueueReq.to_string GenTableQueueReq.parse GenTableQueueReq.marshal)

  TEST "OpenFlow0x04 MultipartReq RoundTrip" =
      let module GenMultipartReq = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReq) in
      (openflow_quickCheck GenMultipartReq.arbitrary
          GenMultipartReq.to_string GenMultipartReq.parse GenMultipartReq.marshal)

  TEST "OpenFlow0x04 MultipartReply.Flow RoundTrip" =
      let module GenFlowReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.FlowStats) in
      (openflow_quickCheck GenFlowReply.arbitrary
          GenFlowReply.to_string GenFlowReply.parse GenFlowReply.marshal)

  TEST "OpenFlow0x04 MultipartReply.Aggregate RoundTrip" =
      let module GenAggregReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.AggregateStats) in
      (openflow_quickCheck GenAggregReply.arbitrary
          GenAggregReply.to_string GenAggregReply.parse GenAggregReply.marshal)

  TEST "OpenFlow0x04 MultipartReply.Table RoundTrip" =
      let module GenTableReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.TableStats) in
      (openflow_quickCheck GenTableReply.arbitrary
          GenTableReply.to_string GenTableReply.parse GenTableReply.marshal)

  TEST "OpenFlow0x04 MultipartReply.PortStats RoundTrip" =
      let module GenPortStatsReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.PortStats) in
      (openflow_quickCheck GenPortStatsReply.arbitrary
          GenPortStatsReply.to_string GenPortStatsReply.parse GenPortStatsReply.marshal)

  TEST "OpenFlow0x04 MultipartReply.SwitchDescriptionReply RoundTrip" =
      let module GenSwDescReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.SwitchDescriptionReply) in
      (openflow_quickCheck GenSwDescReply.arbitrary
          GenSwDescReply.to_string GenSwDescReply.parse GenSwDescReply.marshal)

  TEST "OpenFlow0x04 MultipartReply.GroupFeatures RoundTrip" =
      let module GenGroupFeaturesReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.GroupFeatures) in
      (openflow_quickCheck GenGroupFeaturesReply.arbitrary
          GenGroupFeaturesReply.to_string GenGroupFeaturesReply.parse GenGroupFeaturesReply.marshal)
  
  TEST "OpenFlow0x04 MultipartReply.MeterStats RoundTrip" =
      let module GenMeterStatsReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.MeterStats) in
      (openflow_quickCheck GenMeterStatsReply.arbitrary
          GenMeterStatsReply.to_string GenMeterStatsReply.parse GenMeterStatsReply.marshal)

  TEST "OpenFlow0x04 MultipartReply.MeterConfig RoundTrip" =
      let module GenMeterConfigReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.MeterConfig) in
      (openflow_quickCheck GenMeterConfigReply.arbitrary
          GenMeterConfigReply.to_string GenMeterConfigReply.parse GenMeterConfigReply.marshal)

  TEST "OpenFlow0x04 MultipartReply.MeterFeaturesStats RoundTrip" =
      let module GenMeterFeaturesReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.MeterFeaturesStats) in
      (openflow_quickCheck GenMeterFeaturesReply.arbitrary
          GenMeterFeaturesReply.to_string GenMeterFeaturesReply.parse GenMeterFeaturesReply.marshal)

  TEST "OpenFlow0x04 MultipartReply.GroupDesc RoundTrip" =
      let module GenGroupDescReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.GroupDesc) in
      (openflow_quickCheck GenGroupDescReply.arbitrary
          GenGroupDescReply.to_string GenGroupDescReply.parse GenGroupDescReply.marshal)

  TEST "OpenFlow0x04 MultipartReply.GroupStats RoundTrip" =
      let module GenGroupStatsReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply.GroupStats) in
      (openflow_quickCheck GenGroupStatsReply.arbitrary
          GenGroupStatsReply.to_string GenGroupStatsReply.parse GenGroupStatsReply.marshal)

  TEST "OpenFlow0x04 MultipartReply RoundTrip" =
      let module GenMultipartReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.MultipartReply) in
      (openflow_quickCheck GenMultipartReply.arbitrary
          GenMultipartReply.to_string GenMultipartReply.parse GenMultipartReply.marshal)

  TEST "OpenFlow0x04 QueueDesc.QueueProp RoundTrip" =
      let module GenQueueProp = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.QueueDesc.QueueProp) in
      (openflow_quickCheck GenQueueProp.arbitrary
          GenQueueProp.to_string GenQueueProp.parse GenQueueProp.marshal)

  TEST "OpenFlow0x04 QueueDesc RoundTrip" =
      let module GenQueueDesc = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.QueueDesc) in
      (openflow_quickCheck GenQueueDesc.arbitrary
          GenQueueDesc.to_string GenQueueDesc.parse GenQueueDesc.marshal)

  TEST "OpenFlow0x04 QueueConfReq RoundTrip" =
      let module GenQueueConfReq = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.QueueConfReq) in
      (openflow_quickCheck GenQueueConfReq.arbitrary
          GenQueueConfReq.to_string GenQueueConfReq.parse GenQueueConfReq.marshal)

  TEST "OpenFlow0x04 QueueConfReply RoundTrip" =
      let module GenQueueConfReply = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.QueueConfReply) in
      (openflow_quickCheck GenQueueConfReply.arbitrary
          GenQueueConfReply.to_string GenQueueConfReply.parse GenQueueConfReply.marshal)

  TEST "OpenFlow0x04 PacketOut RoundTrip" =
      let module GenPacketOut = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.PacketOut) in
      (openflow_quickCheck GenPacketOut.arbitrary
          GenPacketOut.to_string GenPacketOut.parse GenPacketOut.marshal)

  TEST "OpenFlow0x04 PacketIn RoundTrip" =
      let module GenPacketIn = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.PacketIn) in
      (openflow_quickCheck GenPacketIn.arbitrary
          GenPacketIn.to_string GenPacketIn.parse GenPacketIn.marshal)

  TEST "OpenFlow0x04 RoleRequest RoundTrip" =
      let module GenRoleReq = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.RoleRequest) in
      (openflow_quickCheck GenRoleReq.arbitrary
          GenRoleReq.to_string GenRoleReq.parse GenRoleReq.marshal)

  TEST "OpenFlow0x04 SwitchConfig RoundTrip" =
      let module GenSwitchConfig = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.SwitchConfig) in
      (openflow_quickCheck GenSwitchConfig.arbitrary
          GenSwitchConfig.to_string GenSwitchConfig.parse GenSwitchConfig.marshal)

  TEST "OpenFlow0x04 TableMod RoundTrip" =
      let module GenTableMod = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.TableMod) in
      (openflow_quickCheck GenTableMod.arbitrary
          GenTableMod.to_string GenTableMod.parse GenTableMod.marshal)

  TEST "OpenFlow0x04 Hello.Element.VersionBitMap RoundTrip" =
      let module GenVersionBitmap = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.Hello.Element.VersionBitMap) in
      (openflow_quickCheck GenVersionBitmap.arbitrary
          GenVersionBitmap.to_string GenVersionBitmap.parse GenVersionBitmap.marshal)

  TEST "OpenFlow0x04 Hello.Element RoundTrip" =
      let module GenElement = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.Hello.Element) in
      (openflow_quickCheck GenElement.arbitrary
          GenElement.to_string GenElement.parse GenElement.marshal)

  TEST "OpenFlow0x04 Hello RoundTrip" =
      let module GenHello = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.Hello) in
      (openflow_quickCheck GenHello.arbitrary
          GenHello.to_string GenHello.parse GenHello.marshal)

  TEST "OpenFlow0x04 FlowRemoved RoundTrip" =
      let module GenFlowRemoved = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.FlowRemoved) in
      (openflow_quickCheck GenFlowRemoved.arbitrary
          GenFlowRemoved.to_string GenFlowRemoved.parse GenFlowRemoved.marshal)

  TEST "OpenFlow0x04 AsyncConfig RoundTrip" =
      let module GenAsyncConfig = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.AsyncConfig) in
      (openflow_quickCheck GenAsyncConfig.arbitrary
          GenAsyncConfig.to_string GenAsyncConfig.parse GenAsyncConfig.marshal)

  TEST "OpenFlow0x04 Error RoundTrip" =
      let module GenError = Gen0x04.OpenFlow0x04_Unsize(Gen0x04.Error) in
      (openflow_quickCheck GenError.arbitrary
          GenError.to_string GenError.parse GenError.marshal)

  TEST "OpenFlow0x05 PortDesc.PortConfig RoundTrip" =
      let module GenPortConfig = Gen0x05.PortDesc.Config in
      (openflow_quickCheck GenPortConfig.arbitrary
          GenPortConfig.to_string GenPortConfig.parse GenPortConfig.marshal)

  TEST "OpenFlow0x05 PortDesc.PortState RoundTrip" =
      let module GenPortState = Gen0x05.PortDesc.State in
      (openflow_quickCheck GenPortState.arbitrary
          GenPortState.to_string GenPortState.parse GenPortState.marshal)

  TEST "OpenFlow0x05 PortDesc.Properties RoundTrip" =
      let module GenProperties = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.PortDesc.Properties) in
      (openflow_quickCheck GenProperties.arbitrary
          GenProperties.to_string GenProperties.parse GenProperties.marshal)

  TEST "OpenFlow0x05 PortDesc RoundTrip" =
      let module PortDesc = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.PortDesc) in
      (openflow_quickCheck PortDesc.arbitrary
          PortDesc.to_string PortDesc.parse PortDesc.marshal)

  TEST "OpenFlow0x05 OfpMatch RoundTrip" =
      let module GenOfpMatch = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.OfpMatch) in
      (openflow_quickCheck GenOfpMatch.arbitrary
          GenOfpMatch.to_string GenOfpMatch.parse GenOfpMatch.marshal)

  TEST "OpenFlow0x05 OfpMatch.Oxm RoundTrip" =
      let module GenOxm = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.OfpMatch.Oxm) in
      (openflow_quickCheck GenOxm.arbitrary
          GenOxm.to_string GenOxm.parse GenOxm.marshal)
  
  TEST "OpenFlow0x05 OfpMatch.OxmHeader RoundTrip" =
      let module GenOxm = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.OfpMatch.OxmHeader) in
      (openflow_quickCheck GenOxm.arbitrary
          GenOxm.to_string GenOxm.parse GenOxm.marshal)

  TEST "OpenFlow0x05 PseudoPort RoundTrip" =
      let module GenPseudoPort = Gen0x05.PseudoPort in
      (openflow_quickCheck GenPseudoPort.arbitrary
          GenPseudoPort.to_string GenPseudoPort.parse GenPseudoPort.marshal)

  TEST "OpenFlow0x05 Action RoundTrip" =
      let module GenAction = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.Action) in
      (openflow_quickCheck GenAction.arbitrary
          GenAction.to_string GenAction.parse GenAction.marshal)

  TEST "OpenFlow0x05 Instructions.Instruction RoundTrip" =
      let module GenInstruction = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.Instructions.Instruction) in
      (openflow_quickCheck GenInstruction.arbitrary
          GenInstruction.to_string GenInstruction.parse GenInstruction.marshal)

  TEST "OpenFlow0x05 Instructions RoundTrip" =
      let module GenInstructions = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.Instructions) in
      (openflow_quickCheck GenInstructions.arbitrary
          GenInstructions.to_string GenInstructions.parse GenInstructions.marshal)

  TEST "OpenFlow0x05 Experimenter RoundTrip" =
      let module GenExperimenter = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.Experimenter) in
      (openflow_quickCheck GenExperimenter.arbitrary
          GenExperimenter.to_string GenExperimenter.parse GenExperimenter.marshal)

  TEST "OpenFlow0x05 SwitchFeatures RoundTrip" =
      let module GenSwitchFeatures = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.SwitchFeatures) in
      (openflow_quickCheck GenSwitchFeatures.arbitrary
          GenSwitchFeatures.to_string GenSwitchFeatures.parse GenSwitchFeatures.marshal)

  TEST "OpenFlow0x05 SwitchConfig RoundTrip" =
      let module GenSwitchConfig = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.SwitchConfig) in
      (openflow_quickCheck GenSwitchConfig.arbitrary
          GenSwitchConfig.to_string GenSwitchConfig.parse GenSwitchConfig.marshal)

  TEST "OpenFlow0x05 TableMod.Properties RoundTrip" =
      let module GenTableProperties = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.TableMod.Properties) in
      (openflow_quickCheck GenTableProperties.arbitrary
          GenTableProperties.to_string GenTableProperties.parse GenTableProperties.marshal)

  TEST "OpenFlow0x05 TableMod RoundTrip" =
      let module GenTableMod = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.TableMod) in
      (openflow_quickCheck GenTableMod.arbitrary
          GenTableMod.to_string GenTableMod.parse GenTableMod.marshal)

  TEST "OpenFlow0x05 FlowMod.Command RoundTrip" =
      let module GenCommand = Gen0x05.FlowMod.FlowModCommand in
      (openflow_quickCheck GenCommand.arbitrary
          GenCommand.to_string GenCommand.parse GenCommand.marshal)

  TEST "OpenFlow0x05 FlowMod RoundTrip" =
      let module GenFlowMod = Gen0x05.OpenFlow0x05_Unsize(Gen0x05.FlowMod) in
      (openflow_quickCheck GenFlowMod.arbitrary
          GenFlowMod.to_string GenFlowMod.parse GenFlowMod.marshal)

  TEST "OpenFlow Hello Test 1" = 
    let open Message in 
    let bs = Cstruct.create 101 in
    let m = Hello bs in 
    let x = 42l in 
    let s = marshal x m in  
    let h = Header.parse (Cstruct.of_string s) in 
    let s' = String.sub s Header.size (h.Header.length - Header.size) in 
    let x',m' = parse h s' in 
    let xid_ok = x = x' in 
    let msg_ok = 
      match m',m with 
	    | Hello bs', Hello bs ->
	      Cstruct.to_string bs = Cstruct.to_string bs'
	    | _ -> 
	      false in 
          xid_ok && msg_ok 
  
  TEST "OpenFlow Vendor Test 1" =
    let open Message in
    let bs = Cstruct.create 101 in
    let bs' = Cstruct.create ((Cstruct.len bs) + 4) in
    let body = "42 is the answer" in
    Cstruct.blit_from_string body 0 bs 0 (String.length body);
    let m = (42l, bs) in
    let _ = Vendor.marshal m bs' in
    let m' = Vendor.parse bs' in    
    match m, m' with
    | (42l, bs), (42l, bs') ->
      Cstruct.to_string bs = Cstruct.to_string bs'
    | _ ->
      false
  
  TEST "OpenFlow StatsReply DescriptionReply Test 1" =
    let open Message in
    let bs' = Cstruct.create 1060 in
    let content = {  
      manufacturer = String.create 256
      ; hardware = String.create 256
      ; software = String.create 256
      ; serial_number = String.create 32
      ; datapath = String.create 256} in
    let m = DescriptionRep content in
    let _ = StatsReply.marshal m bs' in
    let m' = StatsReply.parse bs' in
    match m, m' with
    | DescriptionRep rep, DescriptionRep rep' ->
      rep.manufacturer = rep'.manufacturer &&
      rep.hardware = rep'.hardware &&
      rep.serial_number = rep'.serial_number &&
      rep.datapath = rep'.datapath
    | _ -> 
      false
end

Pa_ounit_lib.Runtime.summarize ()
