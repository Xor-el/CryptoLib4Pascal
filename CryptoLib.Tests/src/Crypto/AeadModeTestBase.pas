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

unit AeadModeTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAeadCipher,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpICipherParameters,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpAesUtilities,
  ClpAesEngine,
  ClpAesBitSlicedEngine,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  BlockCipherTestBase;

type
  /// <summary>
  /// Shared scaffolding for the AEAD block-cipher mode suites (GCM, EAX, OCB,
  /// CCM, GCM-SIV). Holds the engine seam used for multi-engine coverage and
  /// the in-place round-trip harness generalised over <c>IAeadCipher</c>.
  /// Concrete suites keep their own published tests and simply delegate the
  /// shared bodies here.
  /// </summary>
  // A worker rerun once per engine by ForEachExtraEngine.
  TAeadEngineProc = procedure of object;

  TAeadModeTestBase = class abstract(TCryptoLibAlgorithmTestCase)
  strict protected
    // The block-cipher engine factory the current pass builds its mode over.
    // nil => the default AES engine (hardware if available, else scalar).
    FEngineFactory: TBlockCipherFactory;
    // Human label for the engine of the current pass (for failure messages).
    FCurrentEngineLabel: String;

    // The engine for the current pass. Concrete CreateAeadCipher builds its
    // mode over this (OCB calls it twice, for the hash and main ciphers).
    function CurrentEngine: IBlockCipher;

    // Rerun AProc once per NON-default AES engine: the constant-time bit-sliced
    // engine always, and the explicit scalar engine only when the default
    // (utilities) engine is hardware-accelerated (otherwise it already IS the
    // scalar engine, so running it again would be pure duplication). The
    // default-engine pass, and any kernel-toggle sweep, are the caller's job.
    procedure ForEachExtraEngine(AProc: TAeadEngineProc);

    // Build a fresh mode cipher over CurrentEngine. Supplied by the suite.
    function CreateAeadCipher: IAeadCipher; virtual; abstract;
    // Short human label for failure messages (e.g. 'GCM', 'EAX').
    function ModeLabel: String; virtual; abstract;

    // One in-place (output buffer aliases input) round-trip at a single length.
    // Returns '' on success, else a short description of the failing direction.
    function RunInPlaceCase(const ARandom: ISecureRandom;
      APlainLen, AKeyLen: Int32; const AAad: TBytes): String;

    // Drive RunInPlaceCase across ALens, once with a 16-byte key and no AAD and
    // once with a 32-byte key and 20 bytes of AAD, from a fixed seed.
    procedure DoInPlaceSweep(const ALens: array of Int32; ASeed: Int64);
  end;

implementation

// Standalone factories: TBlockCipherFactory is a plain function pointer and
// cannot capture an engine-table index, so each engine gets its own function.
function AeadEngineScalar: IBlockCipher;
begin
  Result := TAesEngine.Create();
end;

function AeadEngineBitSliced: IBlockCipher;
begin
  Result := TAesBitSlicedEngine.Create();
end;

{ TAeadModeTestBase }

function TAeadModeTestBase.CurrentEngine: IBlockCipher;
begin
  if Assigned(FEngineFactory) then
    Result := FEngineFactory()
  else
    Result := TAesUtilities.CreateEngine();
end;

procedure TAeadModeTestBase.ForEachExtraEngine(AProc: TAeadEngineProc);
var
  LSavedFactory: TBlockCipherFactory;
  LSavedLabel: String;
begin
  LSavedFactory := FEngineFactory;
  LSavedLabel := FCurrentEngineLabel;
  try
    FEngineFactory := @AeadEngineBitSliced;
    FCurrentEngineLabel := 'bit-sliced';
    AProc();

    if TAesUtilities.IsHardwareAccelerated() then
    begin
      FEngineFactory := @AeadEngineScalar;
      FCurrentEngineLabel := 'scalar';
      AProc();
    end;
  finally
    FEngineFactory := LSavedFactory;
    FCurrentEngineLabel := LSavedLabel;
  end;
end;

function TAeadModeTestBase.RunInPlaceCase(const ARandom: ISecureRandom;
  APlainLen, AKeyLen: Int32; const AAad: TBytes): String;
var
  LK, LIV, LP, LRef, LBuf: TBytes;
  LParams: IAeadParameters;
  LCipher: IAeadCipher;
  LLen, LTotal: Int32;
begin
  Result := '';
  System.SetLength(LK, AKeyLen);
  ARandom.NextBytes(LK);
  System.SetLength(LIV, 12);
  ARandom.NextBytes(LIV);
  System.SetLength(LP, APlainLen);
  if APlainLen > 0 then
    ARandom.NextBytes(LP);
  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    16 * 8, LIV, AAad);

  // Reference ciphertext||tag, produced out of place.
  LCipher := CreateAeadCipher;
  LCipher.Init(True, LParams as ICipherParameters);
  System.SetLength(LRef, LCipher.GetOutputSize(APlainLen));
  LLen := LCipher.ProcessBytes(LP, 0, APlainLen, LRef, 0);
  LLen := LLen + LCipher.DoFinal(LRef, LLen);
  System.SetLength(LRef, LLen);
  LTotal := LLen;

  // In-place encrypt: the buffer starts as plaintext and is encrypted over itself.
  System.SetLength(LBuf, LTotal);
  if APlainLen > 0 then
    System.Move(LP[0], LBuf[0], APlainLen);
  LCipher := CreateAeadCipher;
  LCipher.Init(True, LParams as ICipherParameters);
  try
    LLen := LCipher.ProcessBytes(LBuf, 0, APlainLen, LBuf, 0);
    LLen := LLen + LCipher.DoFinal(LBuf, LLen);
  except
    on E: Exception do
    begin
      Result := Format('[enc len=%d exc %s] ', [APlainLen, E.Message]);
      Exit;
    end;
  end;
  if (LLen <> LTotal) or (not AreEqual(LBuf, LRef)) then
  begin
    Result := Format('[enc len=%d mismatch] ', [APlainLen]);
    Exit;
  end;

  // In-place decrypt: the buffer starts as ciphertext||tag, decrypted over itself.
  System.SetLength(LBuf, LTotal);
  System.Move(LRef[0], LBuf[0], LTotal);
  LCipher := CreateAeadCipher;
  LCipher.Init(False, LParams as ICipherParameters);
  try
    LLen := LCipher.ProcessBytes(LBuf, 0, LTotal, LBuf, 0);
    LLen := LLen + LCipher.DoFinal(LBuf, LLen);
  except
    on E: Exception do
    begin
      Result := Format('[dec len=%d exc %s] ', [APlainLen, E.Message]);
      Exit;
    end;
  end;
  if LLen <> APlainLen then
  begin
    Result := Format('[dec len=%d got %d] ', [APlainLen, LLen]);
    Exit;
  end;
  System.SetLength(LBuf, LLen);
  if (APlainLen > 0) and (not AreEqual(LBuf, LP)) then
    Result := Format('[dec len=%d mismatch] ', [APlainLen]);
end;

procedure TAeadModeTestBase.DoInPlaceSweep(const ALens: array of Int32;
  ASeed: Int64);
var
  LRnd: ISecureRandom;
  LFails: String;
  LI: Int32;
  LAad: TBytes;
begin
  LRnd := TSecureRandom.Create();
  LRnd.SetSeed(ASeed);
  System.SetLength(LAad, 20);
  LRnd.NextBytes(LAad);
  LFails := '';
  for LI := 0 to High(ALens) do
    LFails := LFails + RunInPlaceCase(LRnd, ALens[LI], 16, nil);
  for LI := 0 to High(ALens) do
    LFails := LFails + RunInPlaceCase(LRnd, ALens[LI], 32, LAad);
  if LFails <> '' then
  begin
    if FCurrentEngineLabel <> '' then
      Fail(Format('in-place %s [%s]: %s', [ModeLabel, FCurrentEngineLabel, LFails]))
    else
      Fail(Format('in-place %s: %s', [ModeLabel, LFails]));
  end;
end;

end.
