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

unit X509UtilitiesTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpAsn1DigestFactory,
  ClpIDigestFactory,
  ClpIMacFactory,
  ClpIStreamCalculator,
  ClpIBlockResult,
  ClpIMac,
  ClpIX509Asn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpX509Asn1Objects,
  ClpAsn1Core,
  ClpAsn1Objects,
  ClpX509Utilities,
  ClpDefaultMacCalculator,
  ClpMacUtilities,
  ClpDigestUtilities,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpPkcsObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestX509Utilities = class(TCryptoLibAlgorithmTestCase)
  strict private
    function MacReference(const AKey, AData: TCryptoLibByteArray): TCryptoLibByteArray;
    function DigestReference(const AData: TCryptoLibByteArray): TCryptoLibByteArray;
    function DerEncode(const AEncodable: IAsn1Encodable): TCryptoLibByteArray;
    function CreateMacFactory(const AKey: TCryptoLibByteArray): IMacFactory;
  published
    procedure TestGenerateMacMatchesDirectHmac;
    procedure TestVerifyMacAcceptsValidMac;
    procedure TestVerifyMacRejectsWrongMac;
    procedure TestMacFactoryAlgorithmDetails;
    procedure TestCalculateDigestFactoryBufferMatchesReference;
    procedure TestCalculateDigestFactoryAsn1EncodableMatchesReference;
    procedure TestCalculateDigestFactoryBufferWithOffsetMatchesReference;
    procedure TestCalculateDigestAlgorithmIdAsn1EncodableMatchesReference;
  end;

implementation

type
  TTestMacFactory = class(TInterfacedObject, IMacFactory)

  strict private
  var
    FMac: IMac;
    FAlgID: IAlgorithmIdentifier;

  public
    constructor Create(const AMac: IMac; const AAlgID: IAlgorithmIdentifier);

    function GetAlgorithmDetails: IAlgorithmIdentifier;
    function CreateCalculator: IStreamCalculator<IBlockResult>;
  end;

{ TTestMacFactory }

constructor TTestMacFactory.Create(const AMac: IMac; const AAlgID: IAlgorithmIdentifier);
begin
  inherited Create();
  FMac := AMac;
  FAlgID := AAlgID;
end;

function TTestMacFactory.GetAlgorithmDetails: IAlgorithmIdentifier;
begin
  Result := FAlgID;
end;

function TTestMacFactory.CreateCalculator: IStreamCalculator<IBlockResult>;
begin
  Result := TDefaultMacCalculator.Create(FMac);
end;

{ TTestX509Utilities }

function TTestX509Utilities.MacReference(const AKey, AData: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LMac: IMac;
begin
  LMac := TMacUtilities.GetMac('HMAC/SHA-256');
  LMac.Init(TKeyParameter.Create(AKey) as IKeyParameter);
  LMac.BlockUpdate(AData, 0, System.Length(AData));
  Result := LMac.DoFinal();
end;

function TTestX509Utilities.DigestReference(const AData: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := TDigestUtilities.CalculateDigest('SHA-256', AData);
end;

function TTestX509Utilities.DerEncode(const AEncodable: IAsn1Encodable): TCryptoLibByteArray;
var
  LStream: TMemoryStream;
begin
  LStream := TMemoryStream.Create;
  try
    AEncodable.EncodeTo(LStream, TAsn1Encodable.Der);
    System.SetLength(Result, LStream.Size);
    if LStream.Size > 0 then
    begin
      LStream.Position := 0;
      LStream.ReadBuffer(Result[0], LStream.Size);
    end;
  finally
    LStream.Free;
  end;
end;

function TTestX509Utilities.CreateMacFactory(const AKey: TCryptoLibByteArray): IMacFactory;
var
  LMac: IMac;
  LAlgID: IAlgorithmIdentifier;
begin
  LMac := TMacUtilities.GetMac('HMAC/SHA-256');
  LMac.Init(TKeyParameter.Create(AKey) as IKeyParameter);
  LAlgID := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdHmacWithSha256);
  Result := TTestMacFactory.Create(LMac, LAlgID);
end;

procedure TTestX509Utilities.TestGenerateMacMatchesDirectHmac;
var
  LKey, LPayload, LDerBytes, LExpected, LActual: TCryptoLibByteArray;
  LEncodable: IAsn1Encodable;
  LMacBitString: IDerBitString;
  LMacFactory: IMacFactory;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LPayload := TEncoding.UTF8.GetBytes('x509 utilities mac generate');
  LEncodable := TDerOctetString.FromContents(LPayload);
  LDerBytes := DerEncode(LEncodable);
  LExpected := MacReference(LKey, LDerBytes);

  LMacFactory := CreateMacFactory(LKey);
  LMacBitString := TX509Utilities.GenerateMac(LMacFactory, LEncodable);
  LActual := LMacBitString.GetOctets();
  CheckTrue(AreEqual(LExpected, LActual));
end;

procedure TTestX509Utilities.TestVerifyMacAcceptsValidMac;
var
  LKey: TCryptoLibByteArray;
  LEncodable: IAsn1Encodable;
  LMacFactory: IMacFactory;
  LMacBitString: IDerBitString;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LEncodable := TDerOctetString.FromContents(
    TEncoding.UTF8.GetBytes('x509 utilities mac verify'));
  LMacFactory := CreateMacFactory(LKey);
  LMacBitString := TX509Utilities.GenerateMac(LMacFactory, LEncodable);
  CheckTrue(TX509Utilities.VerifyMac(LMacFactory, LEncodable, LMacBitString));
end;

procedure TTestX509Utilities.TestVerifyMacRejectsWrongMac;
var
  LKey: TCryptoLibByteArray;
  LEncodable: IAsn1Encodable;
  LMacFactory: IMacFactory;
  LMacBitString, LWrongMac: IDerBitString;
  LWrongBytes: TCryptoLibByteArray;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LEncodable := TDerOctetString.FromContents(
    TEncoding.UTF8.GetBytes('x509 utilities mac reject'));
  LMacFactory := CreateMacFactory(LKey);
  LMacBitString := TX509Utilities.GenerateMac(LMacFactory, LEncodable);

  LWrongBytes := LMacBitString.GetOctets();
  if System.Length(LWrongBytes) > 0 then
    LWrongBytes[0] := LWrongBytes[0] xor $FF;
  LWrongMac := TDerBitString.Create(LWrongBytes);

  CheckFalse(TX509Utilities.VerifyMac(LMacFactory, LEncodable, LWrongMac));
end;

procedure TTestX509Utilities.TestMacFactoryAlgorithmDetails;
var
  LKey: TCryptoLibByteArray;
  LMacFactory: IMacFactory;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LMacFactory := CreateMacFactory(LKey);
  CheckTrue(LMacFactory.AlgorithmDetails.Algorithm.Equals(TPkcsObjectIdentifiers.IdHmacWithSha256));
end;

procedure TTestX509Utilities.TestCalculateDigestFactoryBufferMatchesReference;
var
  LData, LExpected, LActual: TCryptoLibByteArray;
  LDigestFactory: IDigestFactory;
begin
  LData := TEncoding.UTF8.GetBytes('x509 utilities digest buffer');
  LExpected := DigestReference(LData);
  LDigestFactory := TAsn1DigestFactory.Get('SHA-256');
  LActual := TX509Utilities.CalculateDigest(LDigestFactory, LData);
  CheckTrue(AreEqual(LExpected, LActual));
end;

procedure TTestX509Utilities.TestCalculateDigestFactoryAsn1EncodableMatchesReference;
var
  LPayload, LExpected, LActual: TCryptoLibByteArray;
  LEncodable: IAsn1Encodable;
  LDigestFactory: IDigestFactory;
begin
  LPayload := TEncoding.UTF8.GetBytes('x509 utilities digest asn1');
  LEncodable := TDerOctetString.FromContents(LPayload);
  LExpected := DigestReference(DerEncode(LEncodable));
  LDigestFactory := TAsn1DigestFactory.Get('SHA-256');
  LActual := TX509Utilities.CalculateDigest(LDigestFactory, LEncodable);
  CheckTrue(AreEqual(LExpected, LActual));
end;

procedure TTestX509Utilities.TestCalculateDigestFactoryBufferWithOffsetMatchesReference;
var
  LPrefix, LSlice, LBuf, LExpected, LActual: TCryptoLibByteArray;
  LOff, LLen: Int32;
  LDigestFactory: IDigestFactory;
begin
  LPrefix := TEncoding.UTF8.GetBytes('prefix-');
  LSlice := TEncoding.UTF8.GetBytes('x509 utilities digest slice');
  LOff := System.Length(LPrefix);
  LLen := System.Length(LSlice);
  System.SetLength(LBuf, LOff + LLen);
  System.Move(LPrefix[0], LBuf[0], LOff);
  System.Move(LSlice[0], LBuf[LOff], LLen);

  LExpected := DigestReference(LSlice);
  LDigestFactory := TAsn1DigestFactory.Get('SHA-256');
  LActual := TX509Utilities.CalculateDigest(LDigestFactory, LBuf, LOff, LLen);
  CheckTrue(AreEqual(LExpected, LActual));
end;

procedure TTestX509Utilities.TestCalculateDigestAlgorithmIdAsn1EncodableMatchesReference;
var
  LPayload, LExpected, LActual: TCryptoLibByteArray;
  LEncodable: IAsn1Encodable;
  LAlgID: IAlgorithmIdentifier;
begin
  LPayload := TEncoding.UTF8.GetBytes('x509 utilities digest alg id');
  LEncodable := TDerOctetString.FromContents(LPayload);
  LExpected := DigestReference(DerEncode(LEncodable));
  LAlgID := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha256);
  LActual := TX509Utilities.CalculateDigest(LAlgID, LEncodable);
  CheckTrue(AreEqual(LExpected, LActual));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestX509Utilities);
{$ELSE}
  RegisterTest(TTestX509Utilities.Suite);
{$ENDIF FPC}

end.
