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

(* BIP-327 MuSig2 test vectors from https://github.com/bitcoin/bips/tree/master/bip-0327 *)

unit Bip327Vectors;

interface

{$SCOPEDENUMS ON}

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpEncoders,
  JsonVectorParser;

type
  TBip327KeySortVectors = record
    Pubkeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    ExpectedSorted: TCryptoLibGenericArray<TCryptoLibByteArray>;
  end;

  TBip327KeyAggValidCase = record
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Expected: TCryptoLibByteArray;
  end;

  TBip327KeyAggErrorCaseKind = (InvalidContribution, TweakValue);

  TBip327KeyAggErrorCase = record
    Kind: TBip327KeyAggErrorCaseKind;
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Tweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
    IsXonly: TCryptoLibBooleanArray;
    ExpectedSigner: Int32;
    ExpectedContrib: string;
  end;

  TBip327NonceGenCase = record
    RandBytes: TCryptoLibByteArray;
    Sk: TCryptoLibByteArray;
    SkProvided: Boolean;
    Pk: TCryptoLibByteArray;
    AggPk: TCryptoLibByteArray;
    AggPkProvided: Boolean;
    Msg: TCryptoLibByteArray;
    MsgProvided: Boolean;
    ExtraIn: TCryptoLibByteArray;
    ExtraProvided: Boolean;
    ExpectedSecnonce: TCryptoLibByteArray;
    ExpectedPubnonce: TCryptoLibByteArray;
  end;

  TBip327NonceAggValidCase = record
    Pnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Expected: TCryptoLibByteArray;
  end;

  TBip327NonceAggErrorCase = record
    Pnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
    ExpectedSigner: Int32;
    ExpectedContrib: string;
  end;

  TBip327TweakFixtures = record
    Sk: TCryptoLibByteArray;
    Secnonce: TCryptoLibByteArray;
    Pubkeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Pnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Tweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Msg: TCryptoLibByteArray;
    AggNonce: TCryptoLibByteArray;
  end;

  TBip327TweakValidCase = record
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    NoncesForSession: TCryptoLibGenericArray<TCryptoLibByteArray>;
    TweakBytes: TCryptoLibGenericArray<TCryptoLibByteArray>;
    IsXonly: TCryptoLibBooleanArray;
    HasTweaks: Boolean;
    Expected: TCryptoLibByteArray;
  end;

  TBip327TweakErrorCase = record
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    TweakBytes: TCryptoLibGenericArray<TCryptoLibByteArray>;
    IsXonly: TCryptoLibBooleanArray;
  end;

  TBip327SignVerifyFixtures = record
    Sk: TCryptoLibByteArray;
    Pubkeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Pnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Aggnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Msgs: TCryptoLibGenericArray<TCryptoLibByteArray>;
  end;

  TBip327SignVerifyValidCase = record
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    NoncesForSession: TCryptoLibGenericArray<TCryptoLibByteArray>;
    AggNonce: TCryptoLibByteArray;
    Msg: TCryptoLibByteArray;
    Secnonce: TCryptoLibByteArray;
    Expected: TCryptoLibByteArray;
    CheckPartialVerifySigner0: Boolean;
  end;

  TBip327SignVerifySignErrorCaseKind = (InvalidContribution, ValueSecnonce, ValuePubkey);

  TBip327SignVerifySignErrorCase = record
    Kind: TBip327SignVerifySignErrorCaseKind;
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    AggNonce: TCryptoLibByteArray;
    Msg: TCryptoLibByteArray;
    Secnonce: TCryptoLibByteArray;
    ExpectedSigner: Int32;
    ExpectedContrib: string;
    MapAggnonceContribToPubkey: Boolean;
  end;

  TBip327SignVerifyVerifyFailCase = record
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    NoncesForSession: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Sig: TCryptoLibByteArray;
    Msg: TCryptoLibByteArray;
    SignerIndex: Int32;
  end;

  TBip327SignVerifyVerifyErrorCase = record
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    NoncesForSession: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Sig: TCryptoLibByteArray;
    Msg: TCryptoLibByteArray;
    SignerIndex: Int32;
    ExpectedSigner: Int32;
    ExpectedContrib: string;
  end;

  TBip327SigAggFixtures = record
    Pubkeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Psigs: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Tweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Msg: TCryptoLibByteArray;
  end;

  TBip327SigAggValidCase = record
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    TweakBytes: TCryptoLibGenericArray<TCryptoLibByteArray>;
    IsXonly: TCryptoLibBooleanArray;
    HasTweaks: Boolean;
    AggNonce: TCryptoLibByteArray;
    Psigs: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Expected: TCryptoLibByteArray;
  end;

  TBip327SigAggErrorCase = record
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    TweakBytes: TCryptoLibGenericArray<TCryptoLibByteArray>;
    IsXonly: TCryptoLibBooleanArray;
    AggNonce: TCryptoLibByteArray;
    Psigs: TCryptoLibGenericArray<TCryptoLibByteArray>;
    ExpectedSigner: Int32;
    ExpectedContrib: string;
  end;

  TBip327DetSignFixtures = record
    Sk: TCryptoLibByteArray;
    Pubkeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    Msgs: TCryptoLibGenericArray<TCryptoLibByteArray>;
  end;

  TBip327DetSignValidCase = record
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    AggOtherNonce: TCryptoLibByteArray;
    RandBytes: TCryptoLibByteArray;
    RandProvided: Boolean;
    Tweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
    IsXonly: TCryptoLibBooleanArray;
    HasTweaks: Boolean;
    Msg: TCryptoLibByteArray;
    ExpectedPubnonce: TCryptoLibByteArray;
    ExpectedPsig: TCryptoLibByteArray;
  end;

  TBip327DetSignErrorCaseKind = (InvalidContribution, TweakValue, PubkeyValue);

  TBip327DetSignErrorCase = record
    Kind: TBip327DetSignErrorCaseKind;
    Keys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    AggOtherNonce: TCryptoLibByteArray;
    RandBytes: TCryptoLibByteArray;
    RandProvided: Boolean;
    Tweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
    IsXonly: TCryptoLibBooleanArray;
    HasTweaks: Boolean;
    Msg: TCryptoLibByteArray;
    ExpectedSigner: Int32;
    ExpectedContrib: string;
    ExpectAggOtherNonceMapping: Boolean;
  end;

  TBip327VectorBundle = record
    KeySort: TBip327KeySortVectors;
    KeyAggPubkeys: TCryptoLibGenericArray<TCryptoLibByteArray>;
    KeyAggTweaks: TCryptoLibGenericArray<TCryptoLibByteArray>;
    KeyAggValid: TCryptoLibGenericArray<TBip327KeyAggValidCase>;
    KeyAggErrors: TCryptoLibGenericArray<TBip327KeyAggErrorCase>;
    NonceGenCases: TCryptoLibGenericArray<TBip327NonceGenCase>;
    NonceAggPnonces: TCryptoLibGenericArray<TCryptoLibByteArray>;
    NonceAggValid: TCryptoLibGenericArray<TBip327NonceAggValidCase>;
    NonceAggErrors: TCryptoLibGenericArray<TBip327NonceAggErrorCase>;
    Tweak: TBip327TweakFixtures;
    TweakValid: TCryptoLibGenericArray<TBip327TweakValidCase>;
    TweakErrors: TCryptoLibGenericArray<TBip327TweakErrorCase>;
    SignVerify: TBip327SignVerifyFixtures;
    SignVerifyValid: TCryptoLibGenericArray<TBip327SignVerifyValidCase>;
    SignVerifyWrongSigner: TBip327SignVerifyVerifyFailCase;
    SignVerifySignErrors: TCryptoLibGenericArray<TBip327SignVerifySignErrorCase>;
    SignVerifyVerifyFails: TCryptoLibGenericArray<TBip327SignVerifyVerifyFailCase>;
    SignVerifyVerifyErrors: TCryptoLibGenericArray<TBip327SignVerifyVerifyErrorCase>;
    SigAgg: TBip327SigAggFixtures;
    SigAggValid: TCryptoLibGenericArray<TBip327SigAggValidCase>;
    SigAggErrors: TCryptoLibGenericArray<TBip327SigAggErrorCase>;
    DetSign: TBip327DetSignFixtures;
    DetSignValid: TCryptoLibGenericArray<TBip327DetSignValidCase>;
    DetSignErrors: TCryptoLibGenericArray<TBip327DetSignErrorCase>;
  end;

  /// <summary>
  /// BIP-327 MuSig2 test vectors loaded from external JSON files.
  /// </summary>
  TBip327Vectors = class sealed
  strict private
    class var
      GVectorBundle: TBip327VectorBundle;
      GVectorsLoaded: Boolean;
    class procedure EnsureVectorsLoaded;
    class procedure LoadVectorBundle(var ABundle: TBip327VectorBundle);
    class function SelectBytes(const ASource: TCryptoLibGenericArray<TCryptoLibByteArray>;
      const AIndices: TCryptoLibGenericArray<Int32>): TCryptoLibGenericArray<TCryptoLibByteArray>; static;
    class procedure DecodeHexStrings(const AHex: TCryptoLibStringArray;
      out ABytes: TCryptoLibGenericArray<TCryptoLibByteArray>); static;
    class function SessionMsgBytes(const AMsgs: TCryptoLibGenericArray<TCryptoLibByteArray>;
      AIndex: Int32): TCryptoLibByteArray; static;
    class procedure LoadOptionalHexField(const ACaseObj: TJsonVectorObject; const AName: string;
      out ABytes: TCryptoLibByteArray; out AProvided: Boolean); static;
    class procedure LoadKeySortVectors(var ABundle: TBip327VectorBundle);
    class procedure LoadKeyAggVectors(var ABundle: TBip327VectorBundle);
    class procedure LoadNonceGenVectors(var ABundle: TBip327VectorBundle);
    class procedure LoadNonceAggVectors(var ABundle: TBip327VectorBundle);
    class procedure LoadTweakVectors(var ABundle: TBip327VectorBundle);
    class procedure LoadSignVerifyVectors(var ABundle: TBip327VectorBundle);
    class procedure LoadSigAggVectors(var ABundle: TBip327VectorBundle);
    class procedure LoadDetSignVectors(var ABundle: TBip327VectorBundle);
  public
    class function GetKeySort: TBip327KeySortVectors; static;
    class function GetKeyAggValid: TCryptoLibGenericArray<TBip327KeyAggValidCase>; static;
    class function GetKeyAggErrors: TCryptoLibGenericArray<TBip327KeyAggErrorCase>; static;
    class function GetNonceGenCases: TCryptoLibGenericArray<TBip327NonceGenCase>; static;
    class function GetNonceAggValid: TCryptoLibGenericArray<TBip327NonceAggValidCase>; static;
    class function GetNonceAggErrors: TCryptoLibGenericArray<TBip327NonceAggErrorCase>; static;
    class function GetTweak: TBip327TweakFixtures; static;
    class function GetTweakValid: TCryptoLibGenericArray<TBip327TweakValidCase>; static;
    class function GetTweakErrors: TCryptoLibGenericArray<TBip327TweakErrorCase>; static;
    class function GetSignVerify: TBip327SignVerifyFixtures; static;
    class function GetSignVerifyValid: TCryptoLibGenericArray<TBip327SignVerifyValidCase>; static;
    class function GetSignVerifyWrongSigner: TBip327SignVerifyVerifyFailCase; static;
    class function GetSignVerifySignErrors: TCryptoLibGenericArray<TBip327SignVerifySignErrorCase>; static;
    class function GetSignVerifyVerifyFails: TCryptoLibGenericArray<TBip327SignVerifyVerifyFailCase>; static;
    class function GetSignVerifyVerifyErrors: TCryptoLibGenericArray<TBip327SignVerifyVerifyErrorCase>; static;
    class function GetSigAgg: TBip327SigAggFixtures; static;
    class function GetSigAggValid: TCryptoLibGenericArray<TBip327SigAggValidCase>; static;
    class function GetSigAggErrors: TCryptoLibGenericArray<TBip327SigAggErrorCase>; static;
    class function GetDetSign: TBip327DetSignFixtures; static;
    class function GetDetSignValid: TCryptoLibGenericArray<TBip327DetSignValidCase>; static;
    class function GetDetSignErrors: TCryptoLibGenericArray<TBip327DetSignErrorCase>; static;
    class constructor Create;
  end;

implementation

function Bip327VectorDecodeHex(const AData: string): TCryptoLibByteArray;
begin
  Result := THexEncoder.Decode(AData);
end;

{ TBip327Vectors }

class procedure TBip327Vectors.EnsureVectorsLoaded;
begin
  if GVectorsLoaded then
    Exit;
  LoadVectorBundle(GVectorBundle);
  GVectorsLoaded := True;
end;

class procedure TBip327Vectors.LoadVectorBundle(var ABundle: TBip327VectorBundle);
begin
  LoadKeySortVectors(ABundle);
  LoadKeyAggVectors(ABundle);
  LoadNonceGenVectors(ABundle);
  LoadNonceAggVectors(ABundle);
  LoadTweakVectors(ABundle);
  LoadSignVerifyVectors(ABundle);
  LoadSigAggVectors(ABundle);
  LoadDetSignVectors(ABundle);
end;

class function TBip327Vectors.SelectBytes(
  const ASource: TCryptoLibGenericArray<TCryptoLibByteArray>;
  const AIndices: TCryptoLibGenericArray<Int32>): TCryptoLibGenericArray<TCryptoLibByteArray>;
var
  LI: Int32;
begin
  SetLength(Result, System.Length(AIndices));
  for LI := 0 to System.High(AIndices) do
    Result[LI] := ASource[AIndices[LI]];
end;

class procedure TBip327Vectors.DecodeHexStrings(const AHex: TCryptoLibStringArray;
  out ABytes: TCryptoLibGenericArray<TCryptoLibByteArray>);
var
  LI: Int32;
begin
  SetLength(ABytes, System.Length(AHex));
  for LI := 0 to System.High(AHex) do
    ABytes[LI] := Bip327VectorDecodeHex(AHex[LI]);
end;

class function TBip327Vectors.SessionMsgBytes(
  const AMsgs: TCryptoLibGenericArray<TCryptoLibByteArray>; AIndex: Int32)
  : TCryptoLibByteArray;
begin
  Result := AMsgs[AIndex];
  if (Result <> nil) and (System.Length(Result) = 0) then
    Result := nil;
end;

class procedure TBip327Vectors.LoadOptionalHexField(const ACaseObj: TJsonVectorObject;
  const AName: string; out ABytes: TCryptoLibByteArray; out AProvided: Boolean);
begin
  AProvided := False;
  ABytes := nil;
  if not ACaseObj.HasField(AName) then
    Exit;
  if ACaseObj.IsNullField(AName) then
    Exit;
  AProvided := True;
  ABytes := Bip327VectorDecodeHex(ACaseObj.GetString(AName));
end;

class procedure TBip327Vectors.LoadKeySortVectors(var ABundle: TBip327VectorBundle);
var
  LDoc: TJsonVectorDocument;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Bip327/KeySortVectors.json');
  try
    DecodeHexStrings(LDoc.Root.GetStringArray('pubkeys'), ABundle.KeySort.Pubkeys);
    DecodeHexStrings(LDoc.Root.GetStringArray('sorted_pubkeys'), ABundle.KeySort.ExpectedSorted);
  finally
    LDoc.Free;
  end;
end;

class procedure TBip327Vectors.LoadKeyAggVectors(var ABundle: TBip327VectorBundle);
var
  LDoc: TJsonVectorDocument;
  LValidCases, LErrorCases: TCryptoLibGenericArray<TJsonVectorObject>;
  LCase, LError: TJsonVectorObject;
  LI, LCount: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Bip327/KeyAggVectors.json');
  try
    DecodeHexStrings(LDoc.Root.GetStringArray('pubkeys'), ABundle.KeyAggPubkeys);
    DecodeHexStrings(LDoc.Root.GetStringArray('tweaks'), ABundle.KeyAggTweaks);
    LValidCases := LDoc.Root.GetObjectArray('valid_test_cases');
    try
      LCount := System.Length(LValidCases);
      SetLength(ABundle.KeyAggValid, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LValidCases[LI];
        ABundle.KeyAggValid[LI].Keys := SelectBytes(ABundle.KeyAggPubkeys, LCase.GetIntArray('key_indices'));
        ABundle.KeyAggValid[LI].Expected := Bip327VectorDecodeHex(LCase.GetString('expected'));
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LValidCases);
    end;
    LErrorCases := LDoc.Root.GetObjectArray('error_test_cases');
    try
      LCount := System.Length(LErrorCases);
      SetLength(ABundle.KeyAggErrors, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LErrorCases[LI];
        LError := LCase.GetNestedObject('error');
        try
          ABundle.KeyAggErrors[LI].Keys := SelectBytes(ABundle.KeyAggPubkeys, LCase.GetIntArray('key_indices'));
          if SameText(LError.GetString('type'), 'invalid_contribution') then
          begin
            ABundle.KeyAggErrors[LI].Kind := TBip327KeyAggErrorCaseKind.InvalidContribution;
            ABundle.KeyAggErrors[LI].ExpectedSigner := LError.GetErrorSignerIndex('signer');
            ABundle.KeyAggErrors[LI].ExpectedContrib := LError.GetString('contrib');
          end
          else
          begin
            ABundle.KeyAggErrors[LI].Kind := TBip327KeyAggErrorCaseKind.TweakValue;
            ABundle.KeyAggErrors[LI].Tweaks := SelectBytes(ABundle.KeyAggTweaks, LCase.GetIntArray('tweak_indices'));
            ABundle.KeyAggErrors[LI].IsXonly := LCase.GetBoolArray('is_xonly');
          end;
        finally
          LError.Free;
        end;
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LErrorCases);
    end;
  finally
    LDoc.Free;
  end;
end;

class procedure TBip327Vectors.LoadNonceGenVectors(var ABundle: TBip327VectorBundle);
var
  LDoc: TJsonVectorDocument;
  LCases: TCryptoLibGenericArray<TJsonVectorObject>;
  LCase: TJsonVectorObject;
  LI, LCount: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Bip327/NonceGenVectors.json');
  try
    LCases := LDoc.Root.GetObjectArray('test_cases');
    try
      LCount := System.Length(LCases);
      SetLength(ABundle.NonceGenCases, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LCases[LI];
        ABundle.NonceGenCases[LI].RandBytes := Bip327VectorDecodeHex(LCase.GetString('rand_'));
        ABundle.NonceGenCases[LI].Pk := Bip327VectorDecodeHex(LCase.GetString('pk'));
        LoadOptionalHexField(LCase, 'sk', ABundle.NonceGenCases[LI].Sk, ABundle.NonceGenCases[LI].SkProvided);
        LoadOptionalHexField(LCase, 'aggpk', ABundle.NonceGenCases[LI].AggPk, ABundle.NonceGenCases[LI].AggPkProvided);
        LoadOptionalHexField(LCase, 'extra_in', ABundle.NonceGenCases[LI].ExtraIn, ABundle.NonceGenCases[LI].ExtraProvided);
        if LCase.HasField('msg') and not LCase.IsNullField('msg') then
        begin
          ABundle.NonceGenCases[LI].MsgProvided := True;
          ABundle.NonceGenCases[LI].Msg := Bip327VectorDecodeHex(LCase.GetString('msg'));
        end
        else
        begin
          ABundle.NonceGenCases[LI].MsgProvided := False;
          ABundle.NonceGenCases[LI].Msg := nil;
        end;
        ABundle.NonceGenCases[LI].ExpectedSecnonce := Bip327VectorDecodeHex(LCase.GetString('expected_secnonce'));
        ABundle.NonceGenCases[LI].ExpectedPubnonce := Bip327VectorDecodeHex(LCase.GetString('expected_pubnonce'));
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LCases);
    end;
  finally
    LDoc.Free;
  end;
end;

class procedure TBip327Vectors.LoadNonceAggVectors(var ABundle: TBip327VectorBundle);
var
  LDoc: TJsonVectorDocument;
  LValidCases, LErrorCases: TCryptoLibGenericArray<TJsonVectorObject>;
  LCase, LError: TJsonVectorObject;
  LI, LCount: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Bip327/NonceAggVectors.json');
  try
    DecodeHexStrings(LDoc.Root.GetStringArray('pnonces'), ABundle.NonceAggPnonces);
    LValidCases := LDoc.Root.GetObjectArray('valid_test_cases');
    try
      LCount := System.Length(LValidCases);
      SetLength(ABundle.NonceAggValid, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LValidCases[LI];
        ABundle.NonceAggValid[LI].Pnonces := SelectBytes(ABundle.NonceAggPnonces, LCase.GetIntArray('pnonce_indices'));
        ABundle.NonceAggValid[LI].Expected := Bip327VectorDecodeHex(LCase.GetString('expected'));
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LValidCases);
    end;
    LErrorCases := LDoc.Root.GetObjectArray('error_test_cases');
    try
      LCount := System.Length(LErrorCases);
      SetLength(ABundle.NonceAggErrors, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LErrorCases[LI];
        LError := LCase.GetNestedObject('error');
        try
          ABundle.NonceAggErrors[LI].Pnonces := SelectBytes(ABundle.NonceAggPnonces, LCase.GetIntArray('pnonce_indices'));
          ABundle.NonceAggErrors[LI].ExpectedSigner := LError.GetErrorSignerIndex('signer');
          ABundle.NonceAggErrors[LI].ExpectedContrib := LError.GetString('contrib');
        finally
          LError.Free;
        end;
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LErrorCases);
    end;
  finally
    LDoc.Free;
  end;
end;

class procedure TBip327Vectors.LoadTweakVectors(var ABundle: TBip327VectorBundle);
var
  LDoc: TJsonVectorDocument;
  LValidCases, LErrorCases: TCryptoLibGenericArray<TJsonVectorObject>;
  LCase, LError: TJsonVectorObject;
  LI, LCount: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Bip327/TweakVectors.json');
  try
    ABundle.Tweak.Sk := Bip327VectorDecodeHex(LDoc.Root.GetString('sk'));
    ABundle.Tweak.Secnonce := Bip327VectorDecodeHex(LDoc.Root.GetString('secnonce'));
    DecodeHexStrings(LDoc.Root.GetStringArray('pubkeys'), ABundle.Tweak.Pubkeys);
    DecodeHexStrings(LDoc.Root.GetStringArray('pnonces'), ABundle.Tweak.Pnonces);
    DecodeHexStrings(LDoc.Root.GetStringArray('tweaks'), ABundle.Tweak.Tweaks);
    ABundle.Tweak.Msg := Bip327VectorDecodeHex(LDoc.Root.GetString('msg'));
    ABundle.Tweak.AggNonce := Bip327VectorDecodeHex(LDoc.Root.GetString('aggnonce'));
    LValidCases := LDoc.Root.GetObjectArray('valid_test_cases');
    try
      LCount := System.Length(LValidCases);
      SetLength(ABundle.TweakValid, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LValidCases[LI];
        ABundle.TweakValid[LI].Keys := SelectBytes(ABundle.Tweak.Pubkeys, LCase.GetIntArray('key_indices'));
        ABundle.TweakValid[LI].NoncesForSession := SelectBytes(ABundle.Tweak.Pnonces, LCase.GetIntArray('nonce_indices'));
        ABundle.TweakValid[LI].TweakBytes := SelectBytes(ABundle.Tweak.Tweaks, LCase.GetIntArray('tweak_indices'));
        ABundle.TweakValid[LI].HasTweaks := System.Length(ABundle.TweakValid[LI].TweakBytes) > 0;
        if ABundle.TweakValid[LI].HasTweaks then
          ABundle.TweakValid[LI].IsXonly := LCase.GetBoolArray('is_xonly')
        else
          ABundle.TweakValid[LI].IsXonly := nil;
        ABundle.TweakValid[LI].Expected := Bip327VectorDecodeHex(LCase.GetString('expected'));
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LValidCases);
    end;
    LErrorCases := LDoc.Root.GetObjectArray('error_test_cases');
    try
      LCount := System.Length(LErrorCases);
      SetLength(ABundle.TweakErrors, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LErrorCases[LI];
        LError := LCase.GetNestedObject('error');
        try
          ABundle.TweakErrors[LI].Keys := SelectBytes(ABundle.Tweak.Pubkeys, LCase.GetIntArray('key_indices'));
          ABundle.TweakErrors[LI].TweakBytes := SelectBytes(ABundle.Tweak.Tweaks, LCase.GetIntArray('tweak_indices'));
          ABundle.TweakErrors[LI].IsXonly := LCase.GetBoolArray('is_xonly');
        finally
          LError.Free;
        end;
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LErrorCases);
    end;
  finally
    LDoc.Free;
  end;
end;

class procedure TBip327Vectors.LoadSignVerifyVectors(var ABundle: TBip327VectorBundle);
var
  LDoc: TJsonVectorDocument;
  LSecnoncesHex: TCryptoLibStringArray;
  LValidCases, LSignErrors, LVerifyFails, LVerifyErrors: TCryptoLibGenericArray<TJsonVectorObject>;
  LCase, LError: TJsonVectorObject;
  LI, LCount: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Bip327/SignVerifyVectors.json');
  try
    ABundle.SignVerify.Sk := Bip327VectorDecodeHex(LDoc.Root.GetString('sk'));
    DecodeHexStrings(LDoc.Root.GetStringArray('pubkeys'), ABundle.SignVerify.Pubkeys);
    LSecnoncesHex := LDoc.Root.GetStringArray('secnonces');
    DecodeHexStrings(LDoc.Root.GetStringArray('pnonces'), ABundle.SignVerify.Pnonces);
    DecodeHexStrings(LDoc.Root.GetStringArray('aggnonces'), ABundle.SignVerify.Aggnonces);
    DecodeHexStrings(LDoc.Root.GetStringArray('msgs'), ABundle.SignVerify.Msgs);
    LValidCases := LDoc.Root.GetObjectArray('valid_test_cases');
    try
      LCount := System.Length(LValidCases);
      SetLength(ABundle.SignVerifyValid, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LValidCases[LI];
        ABundle.SignVerifyValid[LI].Keys := SelectBytes(ABundle.SignVerify.Pubkeys, LCase.GetIntArray('key_indices'));
        ABundle.SignVerifyValid[LI].NoncesForSession := SelectBytes(ABundle.SignVerify.Pnonces, LCase.GetIntArray('nonce_indices'));
        ABundle.SignVerifyValid[LI].AggNonce := ABundle.SignVerify.Aggnonces[LCase.GetInt('aggnonce_index')];
        ABundle.SignVerifyValid[LI].Msg := SessionMsgBytes(ABundle.SignVerify.Msgs, LCase.GetInt('msg_index'));
        ABundle.SignVerifyValid[LI].Secnonce := Bip327VectorDecodeHex(LSecnoncesHex[LCase.GetInt('secnonce_index', 0)]);
        ABundle.SignVerifyValid[LI].Expected := Bip327VectorDecodeHex(LCase.GetString('expected'));
        ABundle.SignVerifyValid[LI].CheckPartialVerifySigner0 := LI = 0;
        if LI = 0 then
        begin
          ABundle.SignVerifyWrongSigner.Keys := ABundle.SignVerifyValid[LI].Keys;
          ABundle.SignVerifyWrongSigner.NoncesForSession := ABundle.SignVerifyValid[LI].NoncesForSession;
          ABundle.SignVerifyWrongSigner.Sig := ABundle.SignVerifyValid[LI].Expected;
          ABundle.SignVerifyWrongSigner.Msg := SessionMsgBytes(ABundle.SignVerify.Msgs, 0);
          ABundle.SignVerifyWrongSigner.SignerIndex := 1;
        end;
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LValidCases);
    end;
    LSignErrors := LDoc.Root.GetObjectArray('sign_error_test_cases');
    try
      LCount := System.Length(LSignErrors);
      SetLength(ABundle.SignVerifySignErrors, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LSignErrors[LI];
        LError := LCase.GetNestedObject('error');
        try
          ABundle.SignVerifySignErrors[LI].Keys := SelectBytes(ABundle.SignVerify.Pubkeys, LCase.GetIntArray('key_indices'));
          ABundle.SignVerifySignErrors[LI].AggNonce := ABundle.SignVerify.Aggnonces[LCase.GetInt('aggnonce_index')];
          ABundle.SignVerifySignErrors[LI].Msg := SessionMsgBytes(ABundle.SignVerify.Msgs, LCase.GetInt('msg_index'));
          ABundle.SignVerifySignErrors[LI].Secnonce := Bip327VectorDecodeHex(LSecnoncesHex[LCase.GetInt('secnonce_index', 0)]);
          ABundle.SignVerifySignErrors[LI].MapAggnonceContribToPubkey := False;
          if SameText(LError.GetString('type'), 'invalid_contribution') then
          begin
            ABundle.SignVerifySignErrors[LI].Kind := TBip327SignVerifySignErrorCaseKind.InvalidContribution;
            ABundle.SignVerifySignErrors[LI].ExpectedContrib := LError.GetString('contrib');
            if SameText(ABundle.SignVerifySignErrors[LI].ExpectedContrib, 'aggnonce') then
            begin
              ABundle.SignVerifySignErrors[LI].MapAggnonceContribToPubkey := True;
              ABundle.SignVerifySignErrors[LI].ExpectedSigner := -1;
            end
            else
              ABundle.SignVerifySignErrors[LI].ExpectedSigner := LError.GetErrorSignerIndex('signer');
          end
          else if Pos('secnonce', LowerCase(LError.GetString('message'))) > 0 then
            ABundle.SignVerifySignErrors[LI].Kind := TBip327SignVerifySignErrorCaseKind.ValueSecnonce
          else
            ABundle.SignVerifySignErrors[LI].Kind := TBip327SignVerifySignErrorCaseKind.ValuePubkey;
        finally
          LError.Free;
        end;
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LSignErrors);
    end;
    LVerifyFails := LDoc.Root.GetObjectArray('verify_fail_test_cases');
    try
      LCount := System.Length(LVerifyFails);
      SetLength(ABundle.SignVerifyVerifyFails, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LVerifyFails[LI];
        ABundle.SignVerifyVerifyFails[LI].Keys := SelectBytes(ABundle.SignVerify.Pubkeys, LCase.GetIntArray('key_indices'));
        ABundle.SignVerifyVerifyFails[LI].NoncesForSession := SelectBytes(ABundle.SignVerify.Pnonces, LCase.GetIntArray('nonce_indices'));
        ABundle.SignVerifyVerifyFails[LI].Sig := Bip327VectorDecodeHex(LCase.GetString('sig'));
        ABundle.SignVerifyVerifyFails[LI].Msg := SessionMsgBytes(ABundle.SignVerify.Msgs, LCase.GetInt('msg_index'));
        ABundle.SignVerifyVerifyFails[LI].SignerIndex := LCase.GetInt('signer_index');
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LVerifyFails);
    end;
    LVerifyErrors := LDoc.Root.GetObjectArray('verify_error_test_cases');
    try
      LCount := System.Length(LVerifyErrors);
      SetLength(ABundle.SignVerifyVerifyErrors, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LVerifyErrors[LI];
        LError := LCase.GetNestedObject('error');
        try
          ABundle.SignVerifyVerifyErrors[LI].Keys := SelectBytes(ABundle.SignVerify.Pubkeys, LCase.GetIntArray('key_indices'));
          ABundle.SignVerifyVerifyErrors[LI].NoncesForSession := SelectBytes(ABundle.SignVerify.Pnonces, LCase.GetIntArray('nonce_indices'));
          ABundle.SignVerifyVerifyErrors[LI].Sig := Bip327VectorDecodeHex(LCase.GetString('sig'));
          ABundle.SignVerifyVerifyErrors[LI].Msg := SessionMsgBytes(ABundle.SignVerify.Msgs, LCase.GetInt('msg_index'));
          ABundle.SignVerifyVerifyErrors[LI].SignerIndex := LCase.GetInt('signer_index');
          ABundle.SignVerifyVerifyErrors[LI].ExpectedSigner := LError.GetErrorSignerIndex('signer');
          ABundle.SignVerifyVerifyErrors[LI].ExpectedContrib := LError.GetString('contrib');
        finally
          LError.Free;
        end;
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LVerifyErrors);
    end;
  finally
    LDoc.Free;
  end;
end;

class procedure TBip327Vectors.LoadSigAggVectors(var ABundle: TBip327VectorBundle);
var
  LDoc: TJsonVectorDocument;
  LValidCases, LErrorCases: TCryptoLibGenericArray<TJsonVectorObject>;
  LCase, LError: TJsonVectorObject;
  LI, LCount: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Bip327/SigAggVectors.json');
  try
    DecodeHexStrings(LDoc.Root.GetStringArray('pubkeys'), ABundle.SigAgg.Pubkeys);
    DecodeHexStrings(LDoc.Root.GetStringArray('psigs'), ABundle.SigAgg.Psigs);
    DecodeHexStrings(LDoc.Root.GetStringArray('tweaks'), ABundle.SigAgg.Tweaks);
    ABundle.SigAgg.Msg := Bip327VectorDecodeHex(LDoc.Root.GetString('msg'));
    LValidCases := LDoc.Root.GetObjectArray('valid_test_cases');
    try
      LCount := System.Length(LValidCases);
      SetLength(ABundle.SigAggValid, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LValidCases[LI];
        ABundle.SigAggValid[LI].Keys := SelectBytes(ABundle.SigAgg.Pubkeys, LCase.GetIntArray('key_indices'));
        ABundle.SigAggValid[LI].TweakBytes := SelectBytes(ABundle.SigAgg.Tweaks, LCase.GetIntArray('tweak_indices'));
        ABundle.SigAggValid[LI].HasTweaks := System.Length(ABundle.SigAggValid[LI].TweakBytes) > 0;
        if ABundle.SigAggValid[LI].HasTweaks then
          ABundle.SigAggValid[LI].IsXonly := LCase.GetBoolArray('is_xonly')
        else
          ABundle.SigAggValid[LI].IsXonly := nil;
        ABundle.SigAggValid[LI].AggNonce := Bip327VectorDecodeHex(LCase.GetString('aggnonce'));
        ABundle.SigAggValid[LI].Psigs := SelectBytes(ABundle.SigAgg.Psigs, LCase.GetIntArray('psig_indices'));
        ABundle.SigAggValid[LI].Expected := Bip327VectorDecodeHex(LCase.GetString('expected'));
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LValidCases);
    end;
    LErrorCases := LDoc.Root.GetObjectArray('error_test_cases');
    try
      LCount := System.Length(LErrorCases);
      SetLength(ABundle.SigAggErrors, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LErrorCases[LI];
        LError := LCase.GetNestedObject('error');
        try
          ABundle.SigAggErrors[LI].Keys := SelectBytes(ABundle.SigAgg.Pubkeys, LCase.GetIntArray('key_indices'));
          ABundle.SigAggErrors[LI].TweakBytes := SelectBytes(ABundle.SigAgg.Tweaks, LCase.GetIntArray('tweak_indices'));
          ABundle.SigAggErrors[LI].IsXonly := LCase.GetBoolArray('is_xonly');
          ABundle.SigAggErrors[LI].AggNonce := Bip327VectorDecodeHex(LCase.GetString('aggnonce'));
          ABundle.SigAggErrors[LI].Psigs := SelectBytes(ABundle.SigAgg.Psigs, LCase.GetIntArray('psig_indices'));
          ABundle.SigAggErrors[LI].ExpectedSigner := LError.GetErrorSignerIndex('signer');
          ABundle.SigAggErrors[LI].ExpectedContrib := LError.GetString('contrib');
        finally
          LError.Free;
        end;
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LErrorCases);
    end;
  finally
    LDoc.Free;
  end;
end;

class procedure TBip327Vectors.LoadDetSignVectors(var ABundle: TBip327VectorBundle);
var
  LDoc: TJsonVectorDocument;
  LValidCases, LErrorCases: TCryptoLibGenericArray<TJsonVectorObject>;
  LCase, LError: TJsonVectorObject;
  LExpected: TCryptoLibStringArray;
  LI, LCount: Int32;
begin
  LDoc := TJsonVectorDocument.LoadFile('Crypto/Bip327/DetSignVectors.json');
  try
    ABundle.DetSign.Sk := Bip327VectorDecodeHex(LDoc.Root.GetString('sk'));
    DecodeHexStrings(LDoc.Root.GetStringArray('pubkeys'), ABundle.DetSign.Pubkeys);
    DecodeHexStrings(LDoc.Root.GetStringArray('msgs'), ABundle.DetSign.Msgs);
    LValidCases := LDoc.Root.GetObjectArray('valid_test_cases');
    try
      LCount := System.Length(LValidCases);
      SetLength(ABundle.DetSignValid, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LValidCases[LI];
        ABundle.DetSignValid[LI].Keys := SelectBytes(ABundle.DetSign.Pubkeys, LCase.GetIntArray('key_indices'));
        ABundle.DetSignValid[LI].AggOtherNonce := Bip327VectorDecodeHex(LCase.GetString('aggothernonce'));
        if LCase.IsNullField('rand') then
        begin
          ABundle.DetSignValid[LI].RandProvided := False;
          ABundle.DetSignValid[LI].RandBytes := nil;
        end
        else
        begin
          ABundle.DetSignValid[LI].RandProvided := True;
          ABundle.DetSignValid[LI].RandBytes := Bip327VectorDecodeHex(LCase.GetString('rand'));
        end;
        if LCase.HasField('tweaks') and (System.Length(LCase.GetStringArray('tweaks')) > 0) then
        begin
          ABundle.DetSignValid[LI].HasTweaks := True;
          DecodeHexStrings(LCase.GetStringArray('tweaks'), ABundle.DetSignValid[LI].Tweaks);
          ABundle.DetSignValid[LI].IsXonly := LCase.GetBoolArray('is_xonly');
        end
        else
        begin
          ABundle.DetSignValid[LI].HasTweaks := False;
          ABundle.DetSignValid[LI].Tweaks := nil;
          ABundle.DetSignValid[LI].IsXonly := nil;
        end;
        ABundle.DetSignValid[LI].Msg := SessionMsgBytes(ABundle.DetSign.Msgs, LCase.GetInt('msg_index'));
        LExpected := LCase.GetStringArray('expected');
        ABundle.DetSignValid[LI].ExpectedPubnonce := Bip327VectorDecodeHex(LExpected[0]);
        ABundle.DetSignValid[LI].ExpectedPsig := Bip327VectorDecodeHex(LExpected[1]);
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LValidCases);
    end;
    LErrorCases := LDoc.Root.GetObjectArray('error_test_cases');
    try
      LCount := System.Length(LErrorCases);
      SetLength(ABundle.DetSignErrors, LCount);
      for LI := 0 to LCount - 1 do
      begin
        LCase := LErrorCases[LI];
        LError := LCase.GetNestedObject('error');
        try
          ABundle.DetSignErrors[LI].Keys := SelectBytes(ABundle.DetSign.Pubkeys, LCase.GetIntArray('key_indices'));
          ABundle.DetSignErrors[LI].AggOtherNonce := Bip327VectorDecodeHex(LCase.GetString('aggothernonce'));
          if LCase.IsNullField('rand') then
          begin
            ABundle.DetSignErrors[LI].RandProvided := False;
            ABundle.DetSignErrors[LI].RandBytes := nil;
          end
          else
          begin
            ABundle.DetSignErrors[LI].RandProvided := True;
            ABundle.DetSignErrors[LI].RandBytes := Bip327VectorDecodeHex(LCase.GetString('rand'));
          end;
          if LCase.HasField('tweaks') and (System.Length(LCase.GetStringArray('tweaks')) > 0) then
          begin
            ABundle.DetSignErrors[LI].HasTweaks := True;
            DecodeHexStrings(LCase.GetStringArray('tweaks'), ABundle.DetSignErrors[LI].Tweaks);
            ABundle.DetSignErrors[LI].IsXonly := LCase.GetBoolArray('is_xonly');
          end
          else
          begin
            ABundle.DetSignErrors[LI].HasTweaks := False;
            ABundle.DetSignErrors[LI].Tweaks := nil;
            ABundle.DetSignErrors[LI].IsXonly := nil;
          end;
          ABundle.DetSignErrors[LI].Msg := SessionMsgBytes(ABundle.DetSign.Msgs, LCase.GetInt('msg_index'));
          ABundle.DetSignErrors[LI].ExpectAggOtherNonceMapping := False;
          if SameText(LError.GetString('type'), 'invalid_contribution') then
          begin
            ABundle.DetSignErrors[LI].Kind := TBip327DetSignErrorCaseKind.InvalidContribution;
            ABundle.DetSignErrors[LI].ExpectedContrib := LError.GetString('contrib');
            ABundle.DetSignErrors[LI].ExpectedSigner := LError.GetErrorSignerIndex('signer');
            if SameText(ABundle.DetSignErrors[LI].ExpectedContrib, 'aggothernonce') then
              ABundle.DetSignErrors[LI].ExpectAggOtherNonceMapping := True;
          end
          else if Pos('tweak', LowerCase(LError.GetString('message'))) > 0 then
            ABundle.DetSignErrors[LI].Kind := TBip327DetSignErrorCaseKind.TweakValue
          else
            ABundle.DetSignErrors[LI].Kind := TBip327DetSignErrorCaseKind.PubkeyValue;
        finally
          LError.Free;
        end;
      end;
    finally
      TJsonVectorObject.FreeOwnedArray(LErrorCases);
    end;
  finally
    LDoc.Free;
  end;
end;

class function TBip327Vectors.GetKeySort: TBip327KeySortVectors;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.KeySort;
end;

class function TBip327Vectors.GetKeyAggValid: TCryptoLibGenericArray<TBip327KeyAggValidCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.KeyAggValid;
end;

class function TBip327Vectors.GetKeyAggErrors: TCryptoLibGenericArray<TBip327KeyAggErrorCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.KeyAggErrors;
end;

class function TBip327Vectors.GetNonceGenCases: TCryptoLibGenericArray<TBip327NonceGenCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.NonceGenCases;
end;

class function TBip327Vectors.GetNonceAggValid: TCryptoLibGenericArray<TBip327NonceAggValidCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.NonceAggValid;
end;

class function TBip327Vectors.GetNonceAggErrors: TCryptoLibGenericArray<TBip327NonceAggErrorCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.NonceAggErrors;
end;

class function TBip327Vectors.GetTweak: TBip327TweakFixtures;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.Tweak;
end;

class function TBip327Vectors.GetTweakValid: TCryptoLibGenericArray<TBip327TweakValidCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.TweakValid;
end;

class function TBip327Vectors.GetTweakErrors: TCryptoLibGenericArray<TBip327TweakErrorCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.TweakErrors;
end;

class function TBip327Vectors.GetSignVerify: TBip327SignVerifyFixtures;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.SignVerify;
end;

class function TBip327Vectors.GetSignVerifyValid: TCryptoLibGenericArray<TBip327SignVerifyValidCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.SignVerifyValid;
end;

class function TBip327Vectors.GetSignVerifyWrongSigner: TBip327SignVerifyVerifyFailCase;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.SignVerifyWrongSigner;
end;

class function TBip327Vectors.GetSignVerifySignErrors: TCryptoLibGenericArray<TBip327SignVerifySignErrorCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.SignVerifySignErrors;
end;

class function TBip327Vectors.GetSignVerifyVerifyFails: TCryptoLibGenericArray<TBip327SignVerifyVerifyFailCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.SignVerifyVerifyFails;
end;

class function TBip327Vectors.GetSignVerifyVerifyErrors: TCryptoLibGenericArray<TBip327SignVerifyVerifyErrorCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.SignVerifyVerifyErrors;
end;

class function TBip327Vectors.GetSigAgg: TBip327SigAggFixtures;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.SigAgg;
end;

class function TBip327Vectors.GetSigAggValid: TCryptoLibGenericArray<TBip327SigAggValidCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.SigAggValid;
end;

class function TBip327Vectors.GetSigAggErrors: TCryptoLibGenericArray<TBip327SigAggErrorCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.SigAggErrors;
end;

class function TBip327Vectors.GetDetSign: TBip327DetSignFixtures;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.DetSign;
end;

class function TBip327Vectors.GetDetSignValid: TCryptoLibGenericArray<TBip327DetSignValidCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.DetSignValid;
end;

class function TBip327Vectors.GetDetSignErrors: TCryptoLibGenericArray<TBip327DetSignErrorCase>;
begin
  EnsureVectorsLoaded;
  Result := GVectorBundle.DetSignErrors;
end;

class constructor TBip327Vectors.Create;
begin
  EnsureVectorsLoaded;
end;

end.
