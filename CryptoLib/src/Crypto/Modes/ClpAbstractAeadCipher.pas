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

unit ClpAbstractAeadCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpIAeadCipher,
  ClpAeadParameters,
  ClpKeyParameter,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SCannotReuseNonce = 'cannot reuse nonce for %s encryption';
  SMacCheckFailed = 'mac check in %s failed';
  SInvalidMacSize = 'invalid value for MAC size: %d';

type
  /// <summary>
  /// Shared base for the AEAD cipher modes (GCM, EAX, OCB, CCM, GCM-SIV and, in
  /// the stream-cipher family, ChaCha20-Poly1305). Owns the surface that every
  /// AEAD mode repeats: the direction flag, tag size, computed tag block,
  /// initial associated text, and the last (key, nonce) pair used for
  /// nonce-reuse detection; plus the canonical <c>GetMac</c>, constant-time
  /// tag verification, the nonce-reuse guard, MAC-size validation, the unified
  /// "mac check failed" raise, and a guaranteed key-material-wiping destructor.
  /// The per-mode transforms (Init/ProcessBytes/DoFinal/Reset and the fused
  /// kernels) stay in the concrete subclass.
  /// </summary>
  TAbstractAeadCipher = class abstract(TInterfacedObject, IAeadCipher)

  strict protected
  var
    FForEncryption: Boolean;
    FMacSize: Int32;
    // Finalized tag; length is the underlying block size, first FMacSize bytes
    // are the tag. nil before the first successful DoFinal.
    FMacBlock: TCryptoLibByteArray;
    FInitialAssociatedText: TCryptoLibByteArray;
    // Last-used key / nonce, retained for the encrypt-side nonce-reuse guard.
    FLastKey: TCryptoLibByteArray;
    FLastNonce: TCryptoLibByteArray;

    /// <summary>Short mode label used in exception messages (e.g. <c>EAX</c>,
    /// <c>GCM</c>). Distinct from the full <c>AlgorithmName</c>.</summary>
    function GetModeName: String; virtual; abstract;

    /// <summary>
    /// Encrypt-side nonce-reuse guard. On encryption, if the supplied nonce
    /// equals the last one used, refuse unless the key has demonstrably
    /// changed. Byte-identical to the per-mode copies this replaces.
    /// </summary>
    procedure CheckNonceReuse(AForEncryption: Boolean;
      const ANewNonce: TCryptoLibByteArray; const AKeyParam: IKeyParameter);

    /// <summary>Constant-time compare of AMac[AOff .. AOff+FMacSize-1] against
    /// the computed tag block.</summary>
    function VerifyMac(const AMac: TCryptoLibByteArray; AOff: Int32): Boolean;

    /// <summary>Raise the unified "mac check in &lt;mode&gt; failed" error.</summary>
    procedure RaiseMacCheckFailed;

    /// <summary>
    /// Validate a requested MAC size (bits) against [AMinBits, AMaxBits] with a
    /// step of AStepBits, and return the size in bytes. Centralises the check /
    /// raise / shift-to-bytes shared by the modes; each mode supplies its own
    /// bounds (they differ), so this is a plain helper rather than a virtual.
    /// </summary>
    class function ValidateAeadMacSizeBits(ARequestedMacBits, AMinBits,
      AMaxBits, AStepBits: Int32): Int32; static;

    /// <summary>
    /// Zero the mode's secret material. Empty by default; each mode overrides to
    /// wipe its own key-derived arrays. Called by the destructor, and may be
    /// called on re-key. Deliberately does NOT touch FLastKey (the destructor
    /// wipes that once, after this returns).
    /// </summary>
    procedure WipeKeyMaterial(); virtual;

    /// <summary>
    /// Same-key detection + <c>FLastKey</c> maintenance shared by the AEAD
    /// modes, so a re-Init under the same key does no per-message key copy.
    /// Honors two "reuse the key" signals: (a) <c>AKeyParam = nil</c> (the
    /// bc-csharp null-key convention) and (b) <c>AKeyParam</c> holding the same
    /// bytes as the retained <c>FLastKey</c>. In both cases <c>FLastKey</c> is
    /// left intact (no realloc/copy) and True is returned. When the key differs,
    /// the old <c>FLastKey</c> is wiped, a fresh copy is stored, and False is
    /// returned. Constant-time compare. MUST be called AFTER
    /// <c>CheckNonceReuse</c> (both read the pre-update <c>FLastKey</c>).
    /// </summary>
    function SameKeyReuse(const AKeyParam: IKeyParameter): Boolean;

    /// <summary>
    /// Raw-key counterpart of <c>SameKeyReuse</c> for the one-shot packet path,
    /// so the facade never has to wrap the key in an <c>IKeyParameter</c> per
    /// message. Same contract: True (key retained as-is) when AKey is nil (reuse)
    /// or matches the stored key; otherwise wipe + store a fresh copy and return
    /// False. Constant-time compare; call AFTER <c>CheckNonceReuseRaw</c>.
    /// </summary>
    function SameKeyReuseRaw(const AKey: TCryptoLibByteArray): Boolean;

    /// <summary>Raw-key/raw-nonce counterpart of <c>CheckNonceReuse</c> for the
    /// one-shot packet path. Byte-identical guard: on encryption, refuse a
    /// repeated nonce unless the key has demonstrably changed.</summary>
    procedure CheckNonceReuseRaw(AForEncryption: Boolean;
      const ANewNonce, AKey: TCryptoLibByteArray);

    function GetAlgorithmName: String; virtual; abstract;

  public
    destructor Destroy; override;

    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); virtual; abstract;

    /// <summary>
    /// Default one-shot packet init: builds an AeadParameters and defers to Init.
    /// This is NOT the zero-allocation path - modes with a small-buffer packet
    /// cipher override it with a raw InitPacket that skips the parameter objects
    /// and routes key identity through SameKeyReuseRaw.
    /// </summary>
    procedure InitPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad: TCryptoLibByteArray;
      AMacSizeBits: Int32); virtual;

    procedure ProcessAadByte(AInput: Byte); virtual; abstract;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALen: Int32); virtual; abstract;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; virtual; abstract;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual; abstract;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; virtual; abstract;

    /// <summary>Return the finalized tag (FMacSize bytes); zero-filled when no
    /// tag has been produced yet.</summary>
    function GetMac(): TCryptoLibByteArray; virtual;

    function GetUpdateOutputSize(ALen: Int32): Int32; virtual; abstract;
    function GetOutputSize(ALen: Int32): Int32; virtual; abstract;
    procedure Reset(); virtual; abstract;

    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TAbstractAeadCipher }

destructor TAbstractAeadCipher.Destroy;
begin
  WipeKeyMaterial();
  if FLastKey <> nil then
    TArrayUtilities.Fill(FLastKey, 0, System.Length(FLastKey), Byte(0));
  inherited Destroy;
end;

procedure TAbstractAeadCipher.WipeKeyMaterial;
begin
  // no-op by default; concrete modes override to wipe their own material.
end;

procedure TAbstractAeadCipher.InitPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad: TCryptoLibByteArray; AMacSizeBits: Int32);
var
  LKeyParam: IKeyParameter;
begin
  // Compatibility fallback (NOT the zero-allocation path): wrap the raw inputs in
  // parameter objects and defer to Init. A nil key passes a nil key parameter so
  // the mode's own reuse convention still applies.
  if AKey <> nil then
    LKeyParam := TKeyParameter.Create(AKey) as IKeyParameter
  else
    LKeyParam := nil;
  Init(AForEncryption, TAeadParameters.Create(LKeyParam, AMacSizeBits, ANonce,
    AAad) as ICipherParameters);
end;

function TAbstractAeadCipher.SameKeyReuse(const AKeyParam
  : IKeyParameter): Boolean;
begin
  if AKeyParam = nil then
  begin
    // null-key convention: reuse only makes sense once a key was established.
    Result := FLastKey <> nil;
    Exit;
  end;

  if (FLastKey <> nil) and AKeyParam.FixedTimeEquals(FLastKey) then
  begin
    // Same key bytes: keep FLastKey as-is (no realloc, no copy).
    Result := True;
    Exit;
  end;

  // Key changed: wipe the old copy, retain a fresh one for the reuse guard.
  if FLastKey <> nil then
    TArrayUtilities.Fill(FLastKey, 0, System.Length(FLastKey), Byte(0));
  FLastKey := AKeyParam.GetKey();
  Result := False;
end;

function TAbstractAeadCipher.SameKeyReuseRaw(const AKey
  : TCryptoLibByteArray): Boolean;
begin
  if AKey = nil then
  begin
    Result := FLastKey <> nil;
    Exit;
  end;

  if (FLastKey <> nil) and
    (System.Length(FLastKey) = System.Length(AKey)) and
    TArrayUtilities.FixedTimeEquals(FLastKey, AKey) then
  begin
    Result := True;
    Exit;
  end;

  if FLastKey <> nil then
    TArrayUtilities.Fill(FLastKey, 0, System.Length(FLastKey), Byte(0));
  FLastKey := System.Copy(AKey);
  Result := False;
end;

procedure TAbstractAeadCipher.CheckNonceReuseRaw(AForEncryption: Boolean;
  const ANewNonce, AKey: TCryptoLibByteArray);
begin
  if not AForEncryption then
    Exit;

  if (FLastNonce = nil) or (not TArrayUtilities.AreEqual(FLastNonce, ANewNonce))
  then
    Exit;

  if AKey = nil then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce,
      [GetModeName]);

  if (FLastKey <> nil) and (System.Length(FLastKey) = System.Length(AKey)) and
    TArrayUtilities.FixedTimeEquals(FLastKey, AKey) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce,
      [GetModeName]);
end;

procedure TAbstractAeadCipher.CheckNonceReuse(AForEncryption: Boolean;
  const ANewNonce: TCryptoLibByteArray; const AKeyParam: IKeyParameter);
begin
  if not AForEncryption then
    Exit;

  if (FLastNonce = nil) or (not TArrayUtilities.AreEqual(FLastNonce, ANewNonce))
  then
    Exit;

  if AKeyParam = nil then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce,
      [GetModeName]);

  if (FLastKey <> nil) and AKeyParam.FixedTimeEquals(FLastKey) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce,
      [GetModeName]);
end;

function TAbstractAeadCipher.VerifyMac(const AMac: TCryptoLibByteArray;
  AOff: Int32): Boolean;
begin
  Result := TArrayUtilities.FixedTimeEquals(FMacSize, AMac, AOff, FMacBlock, 0);
end;

procedure TAbstractAeadCipher.RaiseMacCheckFailed;
begin
  raise EInvalidCipherTextCryptoLibException.CreateResFmt(@SMacCheckFailed,
    [GetModeName]);
end;

class function TAbstractAeadCipher.ValidateAeadMacSizeBits(ARequestedMacBits,
  AMinBits, AMaxBits, AStepBits: Int32): Int32;
begin
  if (ARequestedMacBits < AMinBits) or (ARequestedMacBits > AMaxBits) or
    ((ARequestedMacBits mod AStepBits) <> 0) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMacSize,
      [ARequestedMacBits]);

  Result := ARequestedMacBits shr 3;
end;

function TAbstractAeadCipher.GetMac: TCryptoLibByteArray;
begin
  if FMacBlock = nil then
    System.SetLength(Result, FMacSize)
  else
    Result := TArrayUtilities.CopyOfRange<Byte>(FMacBlock, 0, FMacSize);
end;

end.
