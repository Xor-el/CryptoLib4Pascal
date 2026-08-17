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
  ClpIPacketCipher,
  ClpAesGcmPacketCipher,
  ClpChaCha20Poly1305PacketCipher,
  ClpAesEaxPacketCipher,
  ClpAesCcmPacketCipher,
  ClpAesOcbPacketCipher,
  ClpCipherUtilities,
  ClpAesUtilities,
  ClpAeadParameters,
  ClpParametersWithIV,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpCryptoLibTypes,
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
    procedure CheckPacket(const APacket: IPacketCipher; AKeyLen, ANonceLen: Int32;
      const AName: String);
    function CreateStream(AMode: Int32): IAeadCipher;
    function CreatePacket(AMode: Int32): IPacketCipher;
    function StreamSeal(const ACipher: IAeadCipher; AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TBytes): TBytes;
    function PacketSeal(const APacket: IPacketCipher; AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TBytes): TBytes;
    procedure CheckDifferential(AMode, AKeyLen, ANonceLen: Int32;
      const AName: String);
  published
    procedure TestAeadModesAcceptEmptyInput;
    procedure TestPacketCiphersZeroLength;
    procedure TestBufferedCiphersAcceptEmptyInput;
    procedure TestPacketMatchesStreaming;
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

procedure TTestAeadEmptyInput.CheckPacket(const APacket: IPacketCipher;
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
  else
    Result := TOcbBlockCipher.Create(TAesUtilities.CreateEngine(),
      TAesUtilities.CreateEngine()) as IAeadCipher;
  end;
end;

function TTestAeadEmptyInput.CreatePacket(AMode: Int32): IPacketCipher;
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
  else
    Result := TAesOcbPacketCipher.GetInstance();
  end;
end;

function TTestAeadEmptyInput.StreamSeal(const ACipher: IAeadCipher;
  AForEncryption: Boolean; const AKey, ANonce, AAad, AInput: TBytes): TBytes;
var
  LOut: TBytes;
  LLen: Int32;
begin
  ACipher.Init(AForEncryption, AeadParams(AKey, ANonce, AAad));
  System.SetLength(LOut, ACipher.GetOutputSize(System.Length(AInput)));
  LLen := 0;
  if System.Length(AInput) > 0 then
    LLen := ACipher.ProcessBytes(AInput, 0, System.Length(AInput), LOut, 0);
  LLen := LLen + ACipher.DoFinal(LOut, LLen);
  System.SetLength(LOut, LLen);
  Result := LOut;
end;

function TTestAeadEmptyInput.PacketSeal(const APacket: IPacketCipher;
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
  CSizes: array [0 .. 5] of Int32 = (0, 1, 16, 17, 40, 100);
var
  LPacket: IPacketCipher;
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
