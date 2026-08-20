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

unit AeadEmptyInputTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIAeadCipher,
  ClpIBufferedCipher,
  ClpGcmBlockCipher,
  ClpChaCha20Poly1305,
  ClpCcmBlockCipher,
  ClpEaxBlockCipher,
  ClpOcbBlockCipher,
  ClpGcmSivBlockCipher,
  ClpIAeadPacketCipher,
  ClpAesGcmPacketCipher,
  ClpChaCha20Poly1305PacketCipher,
  ClpAesEaxPacketCipher,
  ClpAesCcmPacketCipher,
  ClpAesOcbPacketCipher,
  ClpAesGcmSivPacketCipher,
  ClpIBlockPacketCipher,
  ClpAesCbcPacketCipher,
  ClpAesCtrPacketCipher,
  ClpCipherUtilities,
  ClpAesUtilities,
  ClpAeadParameters,
  ClpParametersWithIV,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase;

type
  TTestAeadEmptyInput = class(TCryptoLibAlgorithmTestCase)
  strict private
    function MakeBytes(ALen, ASeed: Int32): TBytes;
    function AeadParams(const AKey, ANonce, AAad: TBytes): ICipherParameters;
    // Seal empty plaintext by EXPLICITLY feeding empty spans through
    // ProcessAadBytes + ProcessBytes (the paths that used to raise on nil).
    function SealEmptyExplicit(const ACipher: IAeadCipher;
      const AKey, ANonce, AAad: TBytes): TBytes;
    // Seal empty plaintext the canonical way: AAD via Init, DoFinal only.
    function SealEmptySkip(const ACipher: IAeadCipher;
      const AKey, ANonce, AAad: TBytes): TBytes;
    procedure CheckMode(const ACipherA, ACipherB: IAeadCipher;
      AKeyLen, ANonceLen: Int32; const AName: String);
    procedure CheckPacket(const APacket: IAeadPacketCipher; AKeyLen, ANonceLen: Int32;
      const AName: String);
    function CreateStream(AMode: Int32): IAeadCipher;
    function CreatePacket(AMode: Int32): IAeadPacketCipher;
    function SealParams(const ACipher: IAeadCipher; AForEncryption: Boolean;
      const AParams: ICipherParameters; const AInput: TBytes): TBytes;
    // nil-key parameter = "reuse the established key" convention.
    function ReuseParams(const ANonce, AAad: TBytes): ICipherParameters;
    function StreamSeal(const ACipher: IAeadCipher; AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TBytes): TBytes;
    function PacketSeal(const APacket: IAeadPacketCipher; AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TBytes): TBytes;
    procedure CheckDifferential(AMode, AKeyLen, ANonceLen: Int32;
      const AName: String);
    function BlockPacketSeal(const APacket: IBlockPacketCipher;
      AForEncryption: Boolean; const AKey, AIV, AInput: TBytes): TBytes;
    function BufferedSeal(const ACipherName: String; AForEncryption: Boolean;
      const AKey, AIV, AInput: TBytes): TBytes;
    procedure CheckBlockMode(const APacket: IBlockPacketCipher;
      const ACipherName: String; const ASizes: array of Int32;
      const AName: String);
  published
    procedure TestAeadModesAcceptEmptyInput;
    procedure TestPacketCiphersZeroLength;
    procedure TestBufferedCiphersAcceptEmptyInput;
    procedure TestPacketMatchesStreaming;
    // Decrypt with a tampered tag through the one-shot packet lane must raise and
    // leave NO recovered plaintext in the caller's output (wiped for the modes
    // that decrypt into it; never written for the SIV mode).
    procedure TestPacketWipesOnMacFailure;
    procedure TestBlockPacketMatchesBuffered;
    // Two-phase key-reuse protocol: a nil-key re-Init reuses the established key
    // (must match an explicit re-key), and a rekey that fails mid-Init must clear
    // the ready flag so a following nil-key reuse raises instead of running on a
    // half-built or wiped schedule.
    procedure TestNilKeyReuseMatchesRekey;
    procedure TestFailedRekeyDefends;
  end;

implementation

function TTestAeadEmptyInput.MakeBytes(ALen, ASeed: Int32): TBytes;
var
  LI: Int32;
begin
  System.SetLength(Result, ALen);
  for LI := 0 to ALen - 1 do
    Result[LI] := Byte((LI * 31 + ASeed * 7 + 3) and $FF);
end;

function TTestAeadEmptyInput.AeadParams(const AKey, ANonce,
  AAad: TBytes): ICipherParameters;
begin
  Result := TAeadParameters.Create(TKeyParameter.Create(AKey) as IKeyParameter,
    128, ANonce, AAad) as ICipherParameters;
end;

function TTestAeadEmptyInput.SealEmptyExplicit(const ACipher: IAeadCipher;
  const AKey, ANonce, AAad: TBytes): TBytes;
var
  LOut, LEmpty: TBytes;
  LLen: Int32;
begin
  System.SetLength(LEmpty, 0); // empty == nil in Pascal
  ACipher.Init(True, AeadParams(AKey, ANonce, nil));
  ACipher.ProcessAadBytes(LEmpty, 0, 0); // must not raise
  if AAad <> nil then
    ACipher.ProcessAadBytes(AAad, 0, System.Length(AAad));
  System.SetLength(LOut, ACipher.GetOutputSize(0));
  LLen := ACipher.ProcessBytes(LEmpty, 0, 0, LOut, 0); // must not raise
  Check(LLen = 0, 'ProcessBytes(empty) must return 0');
  LLen := LLen + ACipher.DoFinal(LOut, LLen);
  System.SetLength(LOut, LLen);
  Result := LOut;
end;

function TTestAeadEmptyInput.SealEmptySkip(const ACipher: IAeadCipher;
  const AKey, ANonce, AAad: TBytes): TBytes;
var
  LOut: TBytes;
  LLen: Int32;
begin
  ACipher.Init(True, AeadParams(AKey, ANonce, AAad));
  System.SetLength(LOut, ACipher.GetOutputSize(0));
  LLen := ACipher.DoFinal(LOut, 0);
  System.SetLength(LOut, LLen);
  Result := LOut;
end;

procedure TTestAeadEmptyInput.CheckMode(const ACipherA, ACipherB: IAeadCipher;
  AKeyLen, ANonceLen: Int32; const AName: String);
var
  LKey, LNonce, LAad, LExplicit, LSkip: TBytes;
begin
  LKey := MakeBytes(AKeyLen, 1);
  LNonce := MakeBytes(ANonceLen, 2);
  LAad := MakeBytes(13, 3);

  // Two fresh instances so the same (key, nonce) is encrypted once each and the
  // encrypt-side nonce-reuse guard is not tripped.
  LExplicit := SealEmptyExplicit(ACipherA, LKey, LNonce, LAad);
  LSkip := SealEmptySkip(ACipherB, LKey, LNonce, LAad);

  CheckEquals(16, System.Length(LExplicit),
    AName + ': empty seal must be a 16-byte tag');
  Check(AreEqual(LExplicit, LSkip),
    AName + ': empty-input seal must equal the skip-ProcessBytes tag');
end;

procedure TTestAeadEmptyInput.CheckPacket(const APacket: IAeadPacketCipher;
  AKeyLen, ANonceLen: Int32; const AName: String);
var
  LKey, LNonce, LAad, LCt, LPt: TBytes;
  LLen: Int32;
begin
  LKey := MakeBytes(AKeyLen, 4);
  LNonce := MakeBytes(ANonceLen, 5);
  LAad := MakeBytes(13, 6);

  System.SetLength(LCt, APacket.GetOutputSize(True, 0, 128));
  LLen := APacket.ProcessPacket(True, LKey, LNonce, LAad, nil, 0, 0, LCt, 0, 128);
  System.SetLength(LCt, LLen);
  CheckEquals(16, LLen, AName + ': 0-length packet seal must be a 16-byte tag');

  System.SetLength(LPt, System.Length(LCt));
  LLen := APacket.ProcessPacket(False, LKey, LNonce, LAad, LCt, 0,
    System.Length(LCt), LPt, 0, 128);
  CheckEquals(0, LLen, AName + ': 0-length packet open must yield 0 bytes');
end;

function TTestAeadEmptyInput.CreateStream(AMode: Int32): IAeadCipher;
begin
  case AMode of
    0:
      Result := TGcmBlockCipher.Create(TAesUtilities.CreateEngine())
        as IAeadCipher;
    1:
      Result := TChaCha20Poly1305.Create() as IAeadCipher;
    2:
      Result := TCcmBlockCipher.Create(TAesUtilities.CreateEngine())
        as IAeadCipher;
    3:
      Result := TEaxBlockCipher.Create(TAesUtilities.CreateEngine())
        as IAeadCipher;
    4:
      Result := TOcbBlockCipher.Create(TAesUtilities.CreateEngine(),
        TAesUtilities.CreateEngine()) as IAeadCipher;
  else
    Result := TGcmSivBlockCipher.Create(TAesUtilities.CreateEngine())
      as IAeadCipher;
  end;
end;

function TTestAeadEmptyInput.CreatePacket(AMode: Int32): IAeadPacketCipher;
begin
  case AMode of
    0:
      Result := TAesGcmPacketCipher.GetInstance();
    1:
      Result := TChaCha20Poly1305PacketCipher.GetInstance();
    2:
      Result := TAesCcmPacketCipher.GetInstance();
    3:
      Result := TAesEaxPacketCipher.GetInstance();
    4:
      Result := TAesOcbPacketCipher.GetInstance();
  else
    Result := TAesGcmSivPacketCipher.GetInstance();
  end;
end;

function TTestAeadEmptyInput.SealParams(const ACipher: IAeadCipher;
  AForEncryption: Boolean; const AParams: ICipherParameters;
  const AInput: TBytes): TBytes;
var
  LOut: TBytes;
  LLen: Int32;
begin
  ACipher.Init(AForEncryption, AParams);
  System.SetLength(LOut, ACipher.GetOutputSize(System.Length(AInput)));
  LLen := 0;
  if System.Length(AInput) > 0 then
    LLen := ACipher.ProcessBytes(AInput, 0, System.Length(AInput), LOut, 0);
  LLen := LLen + ACipher.DoFinal(LOut, LLen);
  System.SetLength(LOut, LLen);
  Result := LOut;
end;

function TTestAeadEmptyInput.ReuseParams(const ANonce,
  AAad: TBytes): ICipherParameters;
begin
  Result := TAeadParameters.Create(nil, 128, ANonce, AAad) as ICipherParameters;
end;

function TTestAeadEmptyInput.StreamSeal(const ACipher: IAeadCipher;
  AForEncryption: Boolean; const AKey, ANonce, AAad, AInput: TBytes): TBytes;
begin
  Result := SealParams(ACipher, AForEncryption, AeadParams(AKey, ANonce, AAad),
    AInput);
end;

function TTestAeadEmptyInput.PacketSeal(const APacket: IAeadPacketCipher;
  AForEncryption: Boolean; const AKey, ANonce, AAad, AInput: TBytes): TBytes;
var
  LOut: TBytes;
  LLen: Int32;
begin
  System.SetLength(LOut, APacket.GetOutputSize(AForEncryption,
    System.Length(AInput), 128));
  LLen := APacket.ProcessPacket(AForEncryption, AKey, ANonce, AAad, AInput, 0,
    System.Length(AInput), LOut, 0, 128);
  System.SetLength(LOut, LLen);
  Result := LOut;
end;

// The one-shot packet path (mode.InitPacket) must be byte-identical to the
// streaming Init/ProcessBytes/DoFinal reference across sizes, and a reused packet
// instance must handle same-key messages, direction flips (enc then dec) and a
// rekey. Guards the per-mode InitPacket overrides against their Init.
procedure TTestAeadEmptyInput.CheckDifferential(AMode, AKeyLen,
  ANonceLen: Int32; const AName: String);
const
  // Spans the block / 2-block / 4-block / 8-block tier boundaries and a large
  // multi-tier payload, so the one-shot packet lane is compared against the
  // streaming lane through every fused width (8-way needs >= 128 bytes).
  CSizes: array [0 .. 17] of Int32 = (0, 1, 15, 16, 17, 31, 32, 33, 40, 63, 64,
    65, 100, 127, 128, 129, 256, 1024);
var
  LPacket: IAeadPacketCipher;
  LKey, LKey2, LNonce, LAad, LPt, LCtP, LCtS, LPt2: TBytes;
  LI: Int32;
begin
  LPacket := CreatePacket(AMode);
  LKey := MakeBytes(AKeyLen, 10);
  LAad := MakeBytes(13, 11);

  for LI := 0 to System.High(CSizes) do
  begin
    LNonce := MakeBytes(ANonceLen, 100 + LI); // distinct nonce per message
    LPt := MakeBytes(CSizes[LI], 20 + LI);

    LCtP := PacketSeal(LPacket, True, LKey, LNonce, LAad, LPt);
    LCtS := StreamSeal(CreateStream(AMode), True, LKey, LNonce, LAad, LPt);
    Check(AreEqual(LCtP, LCtS), AName + ': packet enc must match streaming (size '
      + IntToStr(CSizes[LI]) + ')');

    LPt2 := PacketSeal(LPacket, False, LKey, LNonce, LAad, LCtP);
    Check(AreEqual(LPt2, LPt), AName + ': packet round-trip must recover plaintext'
      + ' (size ' + IntToStr(CSizes[LI]) + ')');
  end;

  // Rekey on the reused instance: a different key must still match streaming.
  LKey2 := MakeBytes(AKeyLen, 77);
  LNonce := MakeBytes(ANonceLen, 250);
  LPt := MakeBytes(40, 9);
  LCtP := PacketSeal(LPacket, True, LKey2, LNonce, LAad, LPt);
  LCtS := StreamSeal(CreateStream(AMode), True, LKey2, LNonce, LAad, LPt);
  Check(AreEqual(LCtP, LCtS), AName + ': packet rekey must match streaming');
end;

procedure TTestAeadEmptyInput.TestPacketMatchesStreaming;
begin
  CheckDifferential(0, 16, 12, 'GCM');
  CheckDifferential(1, 32, 12, 'ChaCha');
  CheckDifferential(2, 16, 12, 'CCM');
  CheckDifferential(3, 16, 12, 'EAX');
  CheckDifferential(4, 16, 12, 'OCB');
  CheckDifferential(5, 16, 12, 'GCM-SIV');
end;

procedure TTestAeadEmptyInput.TestPacketWipesOnMacFailure;
const
  CModes: array [0 .. 5] of Int32 = (0, 1, 2, 3, 4, 5);
  CKeyLens: array [0 .. 5] of Int32 = (16, 32, 16, 16, 16, 16);
  CNames: array [0 .. 5] of String = ('GCM', 'ChaCha', 'CCM', 'EAX', 'OCB',
    'GCM-SIV');
  CPlainLen = 40;
var
  LI, LJ: Int32;
  LPacket: IAeadPacketCipher;
  LKey, LNonce, LAad, LPt, LCt, LOut: TBytes;
  LRaised: Boolean;
begin
  for LI := 0 to System.High(CModes) do
  begin
    LPacket := CreatePacket(CModes[LI]);
    LKey := MakeBytes(CKeyLens[LI], 10 + LI);
    LNonce := MakeBytes(12, 100 + LI);
    LAad := MakeBytes(13, 11);
    LPt := MakeBytes(CPlainLen, 20 + LI);

    LCt := PacketSeal(LPacket, True, LKey, LNonce, LAad, LPt);
    // Corrupt the trailing tag so verification must fail.
    LCt[System.Length(LCt) - 1] := Byte(LCt[System.Length(LCt) - 1] xor $FF);

    // Pre-fill the output with a non-zero sentinel so a wipe is observable.
    System.SetLength(LOut, CPlainLen);
    for LJ := 0 to CPlainLen - 1 do
      LOut[LJ] := $AA;

    LRaised := False;
    try
      LPacket.ProcessPacket(False, LKey, LNonce, LAad, LCt, 0,
        System.Length(LCt), LOut, 0, 128);
    except
      on E: EInvalidCipherTextCryptoLibException do
        LRaised := True;
    end;

    Check(LRaised, CNames[LI] +
      ': tampered tag must raise EInvalidCipherTextCryptoLibException');
    // No recovered plaintext may leak, either way.
    Check(not AreEqual(LOut, LPt), CNames[LI] +
      ': plaintext must not leak on MAC failure');
    // Modes that decrypt into the caller's buffer additionally wipe it to zero;
    // the SIV mode recovers into an internal buffer and never writes on failure.
    if CModes[LI] <> 5 then
      for LJ := 0 to CPlainLen - 1 do
        Check(LOut[LJ] = 0, CNames[LI] +
          ': output must be wiped on MAC failure');
  end;
end;

procedure TTestAeadEmptyInput.TestNilKeyReuseMatchesRekey;

  procedure Once(AMode, AKeyLen, ANonceLen: Int32; const AName: String);
  var
    LCipher: IAeadCipher;
    LKey, LAad, LN1, LN2, LPt1, LPt2, LReuse, LRef: TBytes;
  begin
    LKey := MakeBytes(AKeyLen, 10);
    LAad := MakeBytes(13, 11);
    LN1 := MakeBytes(ANonceLen, 1);
    LN2 := MakeBytes(ANonceLen, 2);
    LPt1 := MakeBytes(24, 3);
    LPt2 := MakeBytes(40, 4);

    LCipher := CreateStream(AMode);
    // Establish the key, then reuse it for a fresh nonce via a nil-key parameter.
    SealParams(LCipher, True, AeadParams(LKey, LN1, LAad), LPt1);
    LReuse := SealParams(LCipher, True, ReuseParams(LN2, LAad), LPt2);
    // A fresh instance keyed explicitly at the same nonce must produce the same.
    LRef := SealParams(CreateStream(AMode), True, AeadParams(LKey, LN2, LAad), LPt2);
    Check(AreEqual(LReuse, LRef),
      AName + ': nil-key reuse must match an explicit re-key');
  end;

begin
  Once(0, 16, 12, 'GCM');
  Once(2, 16, 12, 'CCM');
  Once(3, 16, 12, 'EAX');
  Once(4, 16, 12, 'OCB');
end;

procedure TTestAeadEmptyInput.TestFailedRekeyDefends;

  procedure Once(AMode, AKeyLen, ANonceLen: Int32; const AName: String);
  var
    LCipher: IAeadCipher;
    LKey, LBad, LAad, LN1, LN2, LN3, LPt: TBytes;
    LThrew: Boolean;
  begin
    LKey := MakeBytes(AKeyLen, 10);
    LBad := MakeBytes(AKeyLen + 4, 12); // wrong length: engine rejects during Init
    LAad := MakeBytes(13, 11);
    LN1 := MakeBytes(ANonceLen, 1);
    LN2 := MakeBytes(ANonceLen, 2);
    LN3 := MakeBytes(ANonceLen, 3);
    LPt := MakeBytes(32, 5);

    LCipher := CreateStream(AMode);
    SealParams(LCipher, True, AeadParams(LKey, LN1, LAad), LPt); // establish

    // A rekey that fails mid-Init must clear the ready flag ...
    LThrew := False;
    try
      SealParams(LCipher, True, AeadParams(LBad, LN2, LAad), LPt);
    except
      LThrew := True;
    end;
    Check(LThrew, AName + ': a bad-length rekey must raise');

    // ... so a following nil-key reuse cannot silently run on the half-built
    // (or wiped) schedule: it must raise rather than produce output.
    LThrew := False;
    try
      SealParams(LCipher, True, ReuseParams(LN3, LAad), LPt);
    except
      LThrew := True;
    end;
    Check(LThrew,
      AName + ': nil-key reuse after a failed rekey must raise, not reuse state');
  end;

begin
  Once(0, 16, 12, 'GCM');
  Once(2, 16, 12, 'CCM');
  Once(3, 16, 12, 'EAX');
  Once(4, 16, 12, 'OCB');
end;

function TTestAeadEmptyInput.BlockPacketSeal(const APacket: IBlockPacketCipher;
  AForEncryption: Boolean; const AKey, AIV, AInput: TBytes): TBytes;
var
  LOut: TBytes;
  LLen: Int32;
begin
  System.SetLength(LOut, APacket.GetOutputSize(AForEncryption,
    System.Length(AInput)));
  LLen := APacket.ProcessPacket(AForEncryption, AKey, AIV, AInput, 0,
    System.Length(AInput), LOut, 0);
  System.SetLength(LOut, LLen);
  Result := LOut;
end;

function TTestAeadEmptyInput.BufferedSeal(const ACipherName: String;
  AForEncryption: Boolean; const AKey, AIV, AInput: TBytes): TBytes;
var
  LCipher: IBufferedCipher;
  LOut: TBytes;
  LLen: Int32;
begin
  LCipher := TCipherUtilities.GetCipher(ACipherName);
  LCipher.Init(AForEncryption, TParametersWithIV.Create(TKeyParameter.Create(AKey)
    as IKeyParameter, AIV) as ICipherParameters);
  System.SetLength(LOut, LCipher.GetOutputSize(System.Length(AInput)));
  LLen := 0;
  if System.Length(AInput) > 0 then
    LLen := LCipher.ProcessBytes(AInput, 0, System.Length(AInput), LOut, 0);
  LLen := LLen + LCipher.DoFinal(LOut, LLen);
  System.SetLength(LOut, LLen);
  Result := LOut;
end;

// The block packet path (CBC/CTR) must be byte-identical to the standard
// buffered cipher across sizes, on a reused instance with a direction flip and
// a rekey. CTR takes any length; CBC only whole blocks.
procedure TTestAeadEmptyInput.CheckBlockMode(const APacket: IBlockPacketCipher;
  const ACipherName: String; const ASizes: array of Int32; const AName: String);
var
  LKey, LKey2, LIV, LPt, LCtP, LCtB, LPt2: TBytes;
  LI: Int32;
begin
  LKey := MakeBytes(16, 30);
  for LI := 0 to System.High(ASizes) do
  begin
    LIV := MakeBytes(16, 100 + LI); // distinct IV per message
    LPt := MakeBytes(ASizes[LI], 20 + LI);

    LCtP := BlockPacketSeal(APacket, True, LKey, LIV, LPt);
    LCtB := BufferedSeal(ACipherName, True, LKey, LIV, LPt);
    Check(AreEqual(LCtP, LCtB), AName + ': packet enc must match buffered (size '
      + IntToStr(ASizes[LI]) + ')');

    LPt2 := BlockPacketSeal(APacket, False, LKey, LIV, LCtP);
    Check(AreEqual(LPt2, LPt), AName + ': packet round-trip must recover plaintext'
      + ' (size ' + IntToStr(ASizes[LI]) + ')');
  end;

  // Rekey on the reused instance (also a key-length change: 128 -> 256).
  LKey2 := MakeBytes(32, 77);
  LIV := MakeBytes(16, 250);
  LPt := MakeBytes(64, 9);
  LCtP := BlockPacketSeal(APacket, True, LKey2, LIV, LPt);
  LCtB := BufferedSeal(ACipherName, True, LKey2, LIV, LPt);
  Check(AreEqual(LCtP, LCtB), AName + ': packet rekey must match buffered');
end;

procedure TTestAeadEmptyInput.TestBlockPacketMatchesBuffered;
const
  CCtrSizes: array [0 .. 6] of Int32 = (0, 1, 15, 16, 17, 32, 100);
  CCbcSizes: array [0 .. 3] of Int32 = (0, 16, 32, 64);
begin
  CheckBlockMode(TAesCtrPacketCipher.GetInstance(), 'AES/CTR/NOPADDING',
    CCtrSizes, 'CTR');
  CheckBlockMode(TAesCbcPacketCipher.GetInstance(), 'AES/CBC/NOPADDING',
    CCbcSizes, 'CBC');
end;

procedure TTestAeadEmptyInput.TestAeadModesAcceptEmptyInput;
begin
  CheckMode(TGcmBlockCipher.Create(TAesUtilities.CreateEngine()) as IAeadCipher,
    TGcmBlockCipher.Create(TAesUtilities.CreateEngine()) as IAeadCipher,
    16, 12, 'AES-GCM');
  CheckMode(TChaCha20Poly1305.Create() as IAeadCipher,
    TChaCha20Poly1305.Create() as IAeadCipher, 32, 12, 'ChaCha20-Poly1305');
  CheckMode(TCcmBlockCipher.Create(TAesUtilities.CreateEngine()) as IAeadCipher,
    TCcmBlockCipher.Create(TAesUtilities.CreateEngine()) as IAeadCipher,
    16, 12, 'AES-CCM');
  CheckMode(TEaxBlockCipher.Create(TAesUtilities.CreateEngine()) as IAeadCipher,
    TEaxBlockCipher.Create(TAesUtilities.CreateEngine()) as IAeadCipher,
    16, 12, 'AES-EAX');
  CheckMode(TOcbBlockCipher.Create(TAesUtilities.CreateEngine(),
    TAesUtilities.CreateEngine()) as IAeadCipher,
    TOcbBlockCipher.Create(TAesUtilities.CreateEngine(),
    TAesUtilities.CreateEngine()) as IAeadCipher, 16, 12, 'AES-OCB');
end;

procedure TTestAeadEmptyInput.TestPacketCiphersZeroLength;
begin
  CheckPacket(TAesGcmPacketCipher.GetInstance(), 16, 12, 'GCM-packet');
  CheckPacket(TChaCha20Poly1305PacketCipher.GetInstance(), 32, 12,
    'ChaCha-packet');
  CheckPacket(TAesEaxPacketCipher.GetInstance(), 16, 12, 'EAX-packet');
  CheckPacket(TAesCcmPacketCipher.GetInstance(), 16, 12, 'CCM-packet');
  CheckPacket(TAesOcbPacketCipher.GetInstance(), 16, 12, 'OCB-packet');
  CheckPacket(TAesGcmSivPacketCipher.GetInstance(), 16, 12, 'GCM-SIV-packet');
end;

procedure TTestAeadEmptyInput.TestBufferedCiphersAcceptEmptyInput;
var
  LKey, LIv, LOut, LEmpty: TBytes;
  LCipher: IBufferedCipher;
  LLen: Int32;
begin
  System.SetLength(LEmpty, 0);
  LKey := MakeBytes(16, 7);
  LIv := MakeBytes(16, 8);

  LCipher := TCipherUtilities.GetCipher('AES/CTR/NOPADDING');
  LCipher.Init(True, TParametersWithIV.Create(TKeyParameter.Create(LKey)
    as IKeyParameter, LIv) as ICipherParameters);
  System.SetLength(LOut, 16);
  LLen := LCipher.ProcessBytes(LEmpty, 0, 0, LOut, 0); // must not raise
  CheckEquals(0, LLen, 'CTR ProcessBytes(empty) must return 0');

  LCipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  LCipher.Init(True, TParametersWithIV.Create(TKeyParameter.Create(LKey)
    as IKeyParameter, LIv) as ICipherParameters);
  // A whole 0-length CBC/PKCS7 message finalizes to exactly one padded block.
  System.SetLength(LOut, LCipher.GetOutputSize(0));
  LLen := LCipher.ProcessBytes(LEmpty, 0, 0, LOut, 0); // must not raise
  CheckEquals(0, LLen, 'CBC ProcessBytes(empty) must return 0');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAeadEmptyInput);
{$ELSE}
  RegisterTest(TTestAeadEmptyInput.Suite);
{$ENDIF FPC}

end.
