{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCipherKernelBinding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIScheduleEpoch,
  ClpCipherKernelTypes;

type
  /// <summary>
  ///   Per-binding acquisition gate: answers "must I re-run my typed
  ///   TryAcquireX?" so a mode acquires an accelerated kernel once and reuses it
  ///   across messages instead of walking the registry every Init. It holds only
  ///   the gate state, never the kernel - the mode keeps its own typed kernel
  ///   field; a mode with two kernels holds two bindings. Shared identically by
  ///   AEAD and plain block modes (it neither knows nor cares about its owner's
  ///   class), which is what removes the copy-pasted nil/direction/rekey checks.
  ///   <para>Two policies: NeedsRebind for kernels bound to an engine's key
  ///   schedule (invalidated by the engine's rebuild epoch), NeedsResolve for
  ///   engine-independent kernels (resolved once, re-checked only on a direction
  ///   change). A cached binding is NOT invalidated by a runtime change to the
  ///   registered kernels: register (or unregister) kernel factories before
  ///   creating the ciphers that use them - the framework's own factories all
  ///   register at unit initialization. Not thread-safe: single-threaded per
  ///   instance, like its owner. Hold it as a field; never copy it by value.</para>
  /// </summary>
  TCipherKernelBinding = record
  strict private
  var
    FEpochSource: IScheduleEpoch;      // engine's epoch view; nil if unsupported
    FProbed: Boolean;                  // engine QI performed once
    FBound: Boolean;                   // at least one acquire decision recorded
    FEpoch: UInt32;                    // engine schedule epoch at last bind
    FDirection: TCipherKernelDirection; // direction at last bind
  public
    /// <summary>
    ///   Epoch policy, for kernels bound to an engine's round-key buffer. True
    ///   =&gt; the caller MUST re-run its typed TryAcquireX (and any companion
    ///   capability probe) NOW; the gate records the new (epoch, direction)
    ///   before returning, so there is no follow-up commit to forget.
    ///   On True the caller must nil-then-reacquire its kernel field - never keep
    ///   the old kernel, whose keys pointer may be dead. False =&gt; every cached
    ///   handle is still valid. AEngine not implementing IScheduleEpoch always
    ///   yields True (unconditional re-acquire, matching pre-gate behavior).
    /// </summary>
    function NeedsRebind(const AEngine: IBlockCipher;
      ADirection: TCipherKernelDirection): Boolean;

    /// <summary>
    ///   Resolve-once policy, for engine-independent kernels (e.g. a POLYVAL
    ///   kernel over a caller-owned power table, or a stream-cipher poly kernel).
    ///   True only on the first call and on a direction change; the schedule
    ///   epoch is irrelevant here. (Register kernels before first use - a runtime
    ///   registry change does not re-trigger a resolve on an existing binding.)
    /// </summary>
    function NeedsResolve(ADirection: TCipherKernelDirection): Boolean;

    /// <summary>Force re-acquisition on the next Needs* call (mode teardown or an
    /// explicit rebind).</summary>
    procedure Invalidate;
  end;

implementation

{ TCipherKernelBinding }

function TCipherKernelBinding.NeedsRebind(const AEngine: IBlockCipher;
  ADirection: TCipherKernelDirection): Boolean;
var
  LEpoch: UInt32;
begin
  if not FProbed then
  begin
    if not Supports(AEngine, IScheduleEpoch, FEpochSource) then
      FEpochSource := nil;
    FProbed := True;
  end;

  if FEpochSource = nil then
  begin
    // Engine cannot report a rebuild epoch: fall back to always re-acquiring.
    Result := True;
    Exit;
  end;

  LEpoch := FEpochSource.GetScheduleEpoch;
  if FBound and (FEpoch = LEpoch) and (FDirection = ADirection) then
  begin
    Result := False;
    Exit;
  end;

  FBound := True;
  FEpoch := LEpoch;
  FDirection := ADirection;
  Result := True;
end;

function TCipherKernelBinding.NeedsResolve(
  ADirection: TCipherKernelDirection): Boolean;
begin
  if FBound and (FDirection = ADirection) then
  begin
    Result := False;
    Exit;
  end;

  FBound := True;
  FDirection := ADirection;
  Result := True;
end;

procedure TCipherKernelBinding.Invalidate;
begin
  FBound := False;
end;

end.
