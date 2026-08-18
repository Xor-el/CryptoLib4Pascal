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
  TAbstractAesEngine = class abstract(TInterfacedObject)

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
      const AKey: TCryptoLibByteArray): Boolean;

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
    destructor Destroy; override;
  end;

implementation

{ TAbstractAesEngine }

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
  // succeeds and calls MarkScheduleBuilt.
  FScheduleReady := False;
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
