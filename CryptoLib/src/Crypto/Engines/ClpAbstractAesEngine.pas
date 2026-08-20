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

unit ClpAbstractAesEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIScheduleEpoch,
  ClpIRawKeyedCipher,
  ClpIBlockCipher,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpKeyParameter,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Shared base for the AES engine variants. Owns the same-key/direction gate so that a
  /// re-Init under the same key and direction reuses the existing key schedule
  /// instead of recomputing it - the dominant fixed cost of small-buffer
  /// CTR/CBC/ECB, which re-Init the engine once per message. The actual key
  /// expansion and its storage stay in each concrete engine; this base only
  /// tracks the last (direction, key) and decides whether a rebuild is needed.
  /// <para>Timing note: the gate makes Init's cost depend on whether the key
  /// changed, not on its value (the compare is constant-time). It is not intended
  /// for keys derived from secret content (e.g. convergent encryption), where
  /// key-equality would reveal content-equality.</para>
  /// </summary>
  TAbstractAesEngine = class abstract(TInterfacedObject, IScheduleEpoch,
    IRawKeyedCipher)

  strict protected
  var
    /// <summary>Copy of the key the current schedule was built from; nil until
    /// the first successful build. Retained for the reuse comparison and wiped
    /// on rekey and on destroy.</summary>
    FLastKey: TCryptoLibByteArray;
    /// <summary>Direction the current schedule was built for (encrypt vs the
    /// in-place inverse-key decrypt schedule).</summary>
    FLastForEncryption: Boolean;
    /// <summary>True only while FLastKey/FLastForEncryption describe a fully
    /// built, valid schedule. Cleared before a (destructive) rebuild and set
    /// again only after the rebuild succeeds, so a failed Init never leaves a
    /// stale schedule marked reusable.</summary>
    FScheduleReady: Boolean;
    /// <summary>Monotonic count of destructive schedule rebuilds. Bumped the
    /// moment CanReuseSchedule enters the rebuild path (not on success), so a
    /// kernel bound to the old round-key buffer is treated as stale from the
    /// instant the rebuild starts, mirroring FScheduleReady's invalidate-on-entry.
    /// A same-key reuse leaves it untouched. Surfaced via GetScheduleEpoch.</summary>
    FScheduleEpoch: UInt32;

    /// <summary>
    /// Returns True when the existing schedule can be reused for
    /// (AForEncryption, AKey) - a ready schedule, matching direction, and a
    /// matching key (length checked openly, bytes compared in constant time).
    /// On any mismatch it clears FScheduleReady (the following rebuild is
    /// destructive) and returns False; it records nothing, so an expansion that
    /// then throws cannot leave stale bookkeeping. The caller must, after a
    /// successful rebuild, call MarkScheduleBuilt as its last step.
    /// </summary>
    function CanReuseSchedule(AForEncryption: Boolean;
      const AKey: TCryptoLibByteArray): Boolean; overload;
    /// <summary>Same-key gate for the parameter path: compares AKeyParam against
    /// the retained key WITHOUT materializing it (GetKeyLength + constant-time
    /// FixedTimeEquals), so a same-key re-Init copies nothing and wipes nothing.
    /// Same invalidate-on-miss contract as the byte-array overload.</summary>
    function CanReuseSchedule(AForEncryption: Boolean;
      const AKeyParam: IKeyParameter): Boolean; overload;

    /// <summary>
    /// Records (AForEncryption, AKey) and marks the schedule ready. Call once,
    /// as the final step of a successful rebuild. Wipes the previous key copy.
    /// </summary>
    procedure MarkScheduleBuilt(AForEncryption: Boolean;
      const AKey: TCryptoLibByteArray);

    /// <summary>
    /// Zeroize (and, where applicable, free) the engine's key-derived material
    /// - round keys / working key / substitution tables. Abstract so every
    /// engine must provide it: forgetting to wipe key material would otherwise
    /// pass silently. It is the single wipe path (the base destructor calls it;
    /// engines should route their own teardown through it rather than a separate
    /// destructor), so it MUST be idempotent and nil-safe. Wipe on destroy,
    /// never on Reset (modes reuse the cipher after Reset).
    /// </summary>
    procedure WipeSchedule; virtual; abstract;

  public
    /// <summary>IScheduleEpoch: the current schedule-rebuild generation (see
    /// FScheduleEpoch). Lets a kernel-binding gate cheaply detect that the round
    /// keys were rebuilt and re-acquire, without exposing the key.</summary>
    function GetScheduleEpoch: UInt32;

    /// <summary>IRawKeyedCipher: raw-key (re)init. Compare-only same-key fast
    /// path (no allocation, no key copy); on a real rebuild it wraps the key once
    /// and defers to the standard Init, so the key-expansion path stays in one
    /// place. Inherited by every engine - none override it.</summary>
    procedure InitRaw(AForEncryption: Boolean;
      const AKey: TCryptoLibByteArray);

    destructor Destroy; override;
  end;

implementation

{ TAbstractAesEngine }

function TAbstractAesEngine.GetScheduleEpoch: UInt32;
begin
  Result := FScheduleEpoch;
end;

procedure TAbstractAesEngine.InitRaw(AForEncryption: Boolean;
  const AKey: TCryptoLibByteArray);
var
  LCipher: IBlockCipher;
begin
  // Hot path: the schedule is already built for this exact key -> reuse it, no
  // allocation and no key copy.
  if CanReuseSchedule(AForEncryption, AKey) then
    Exit;
  // Rare rebuild: wrap the raw key once and defer to the standard Init (which
  // re-validates and rebuilds), so the key-expansion path lives in one place.
  // Self is the concrete engine, which implements IBlockCipher; the calling mode
  // holds a reference, so this QI never drops the last one.
  if Supports(Self, IBlockCipher, LCipher) then
    LCipher.Init(AForEncryption, TKeyParameter.Create(AKey) as ICipherParameters);
end;

destructor TAbstractAesEngine.Destroy;
begin
  WipeSchedule;
  if FLastKey <> nil then
    TArrayUtilities.Fill(FLastKey, 0, System.Length(FLastKey), Byte(0));
  FLastKey := nil;
  FScheduleReady := False;
  inherited Destroy;
end;

function TAbstractAesEngine.CanReuseSchedule(AForEncryption: Boolean;
  const AKey: TCryptoLibByteArray): Boolean;
begin
  if FScheduleReady and (FLastForEncryption = AForEncryption) and
    (FLastKey <> nil) and (System.Length(FLastKey) = System.Length(AKey)) and
    TArrayUtilities.FixedTimeEquals(System.Length(AKey), FLastKey, 0, AKey, 0) then
  begin
    Result := True;
    Exit;
  end;

  // Entering the rebuild path: it is destructive (it frees/overwrites the round
  // keys), so invalidate immediately. Nothing is recorded until the rebuild
  // succeeds and calls MarkScheduleBuilt. The epoch bump makes every kernel
  // bound to the old round keys re-acquire on its next use.
  FScheduleReady := False;
  System.Inc(FScheduleEpoch);
  Result := False;
end;

function TAbstractAesEngine.CanReuseSchedule(AForEncryption: Boolean;
  const AKeyParam: IKeyParameter): Boolean;
begin
  if FScheduleReady and (FLastForEncryption = AForEncryption) and
    (FLastKey <> nil) and (System.Length(FLastKey) = AKeyParam.GetKeyLength()) and
    AKeyParam.FixedTimeEquals(FLastKey) then
  begin
    Result := True;
    Exit;
  end;

  FScheduleReady := False;
  System.Inc(FScheduleEpoch);
  Result := False;
end;

procedure TAbstractAesEngine.MarkScheduleBuilt(AForEncryption: Boolean;
  const AKey: TCryptoLibByteArray);
begin
  FLastForEncryption := AForEncryption;
  if (FLastKey = nil) or (System.Length(FLastKey) <> System.Length(AKey)) then
  begin
    if FLastKey <> nil then
      TArrayUtilities.Fill(FLastKey, 0, System.Length(FLastKey), Byte(0));
    FLastKey := System.Copy(AKey);
  end
  else
    System.Move(AKey[0], FLastKey[0], System.Length(AKey));
  FScheduleReady := True;
end;

end.
