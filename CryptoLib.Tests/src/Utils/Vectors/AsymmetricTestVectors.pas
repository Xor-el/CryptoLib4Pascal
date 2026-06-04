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

unit AsymmetricTestVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

{$SCOPEDENUMS ON}

uses
  SysUtils,
  ClpBigInteger,
  ClpConverters,
  ClpCryptoLibTypes,
  ClpDigestUtilities,
  ClpDsaParameters,
  ClpECCurve,
  ClpECParameters,
  ClpEncoders,
  FixedSecureRandom,
  ClpIAsymmetricKeyParameter,
  ClpIDSADigestSigner,
  ClpIDsaParameters,
  ClpIECCommon,
  ClpIECParameters,
  ClpIRsaParameters,
  ClpISecureRandom,
  ClpPrivateKeyFactory,
  ClpPublicKeyFactory,
  CsvVectorLoaderBase,
  CsvVectorParser,
  JsonVectorParser,
  TestKeyBuilders;

type
  TPssVectorRow = record
      ExampleId, SubCase: string;
      TestId: Integer;
      Modulus, PubExp, PrivExp, P, Q, DP, DQ, QInv: string;
      MsgHex, SaltHex, SigHex: string;
    end;

  /// <summary>
  /// RFC 3447 RSA-PSS test vectors loaded from external CSV.
  /// </summary>
  TPssVectors = class sealed
  strict private
    class var
      FAllRows: TCryptoLibGenericArray<TPssVectorRow>;
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TPssVectorRow; static;
  public
    class function GetRows: TCryptoLibGenericArray<TPssVectorRow>; static;
    class function GetRowByTestId(const ATestId: Integer): TPssVectorRow; static;
    class function GetExampleKeyRow(const AExampleId: string): TPssVectorRow; static;
    class function CreatePublicKey(const ARow: TPssVectorRow): IRsaKeyParameters; static;
    class function CreatePrivateCrtKey(const ARow: TPssVectorRow)
      : IRsaPrivateCrtKeyParameters; static;
    class function DecodeMsg(const ARow: TPssVectorRow): TCryptoLibByteArray; static;
    class function DecodeSalt(const ARow: TPssVectorRow): TCryptoLibByteArray; static;
    class function DecodeSig(const ARow: TPssVectorRow): TCryptoLibByteArray; static;
    class constructor Create;
  end;

  TOaepKeySetRow = record
      KeySetId, KeyType: string;
      Modulus, PubExp, PrivExp, P, Q, DP, DQ, QInv: string;
      PubDerHex, PrivDerHex: string;
    end;

  TOaepVectorRow = record
    VectorId, KeySetId, VectorNo, SeedHex, SeedSource: string;
    InputHex, OutputHex, OaepDigest, OaepMgf: string;
  end;

  /// <summary>
  /// RSA-OAEP test vectors loaded from external CSV corpora with inline DER hex key sets.
  /// </summary>
  TOaepVectors = class sealed
  strict private
    class var
      FKeySets: TCryptoLibGenericArray<TOaepKeySetRow>;
      FKeySetTable: TCsvVectorTable;
      FManifestRows: TCryptoLibGenericArray<TOaepVectorRow>;
      FManifestTable: TCsvVectorTable;

    class function KeySetFromCsv(const ARow: TCsvRow): TOaepKeySetRow; static;
    class function ManifestFromCsv(const ARow: TCsvRow): TOaepVectorRow; static;
    class function FindKeySetIndex(const AKeySetId: string): Integer; static;
    class function ToCrtRecord(const AKeySet: TOaepKeySetRow): TRsaCrtHexRecord; static;
  public
    class function GetKeySet(const AKeySetId: string): TOaepKeySetRow; static;
    class function GetManifestRows: TCryptoLibGenericArray<TOaepVectorRow>; static;
    class function GetManifestRowsByKeySet(const AKeySetId: string)
      : TCryptoLibGenericArray<TOaepVectorRow>; static;
    class function CreatePublicKey(const AKeySet: TOaepKeySetRow): IAsymmetricKeyParameter; static;
    class function CreatePrivateKey(const AKeySet: TOaepKeySetRow): IAsymmetricKeyParameter; static;
    class function DecodeHexField(const AHex: string): TCryptoLibByteArray; static;
    class function ResolveSeedBytes(const AVector: TOaepVectorRow;
      const AKeySet: TOaepKeySetRow): TCryptoLibByteArray; static;
    class constructor Create;
  end;

  TIso9796VectorRow = record
      TestId, ModulusHex, PubExpHex, PriExpHex, MessageHex: string;
      SignatureHex, SignSubtrahendHex, GenerationCompare: string;
      PadBits, SigCompareOffset, MsgCompareOffset: Integer;
    end;

  /// <summary>
  /// ISO 9796-1 test vectors loaded from external CSV.
  /// </summary>
  TIso9796Vectors = class sealed
  strict private
    class var
      FAllRows: TCryptoLibGenericArray<TIso9796VectorRow>;
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TIso9796VectorRow; static;
    class function GetField(const ARow: TCsvRow; const AName: string): string; static;
  public
    class function GetRows: TCryptoLibGenericArray<TIso9796VectorRow>; static;
    class function GetRow(const ATestId: string): TIso9796VectorRow; static;
    class function ComputeExpectedSignature(const ARow: TIso9796VectorRow)
      : TCryptoLibByteArray; static;
    class constructor Create;
  end;

  TDsaFips1863Row = record
      DigestName: string;
      PHex, QHex, GHex, XHex, YHex, KBigInt, KPadHex, MessageHex: string;
      ExpectedRHex, ExpectedSHex: string;
    end;

  TDsaParamGenExpected = record
    Counter: Int32;
    PHex, QHex, GHex: string;
  end;

  TDsaFips1862ParamGen = record
    DigestName: string;
    L, N, Certainty: Int32;
    SeedHex, RandomType: string;
    Expected: TDsaParamGenExpected;
  end;

  TDsaFips1862KeyGen = record
    RandomType, PrivateSeedHex, ExpectedXHex, ExpectedYHex: string;
  end;

  TDsaFips1862Sign = record
    KBigInt, KPadHex, MessageHex, ExpectedRHex, ExpectedSHex: string;
  end;

  TDsaFips1862GoldenCase = record
    TestId: string;
    ParamGen: TDsaFips1862ParamGen;
    KeyGen: TDsaFips1862KeyGen;
    Sign: TDsaFips1862Sign;
  end;

  TDsa512GenCase = record
    ParamGenRandom: TCryptoLibStringArray;
    L, N, Certainty, ExpectedCounter: Int32;
    ExpectedPHex, ExpectedQHex: string;
    KeyGenRandom: TCryptoLibStringArray;
    KeyGenPadHex, MessageDecimal, ExpectedR, ExpectedS: string;
  end;

  TDsa2ParametersCase = record
    SeedHex, DigestName: string;
    L, N, Certainty: Int32;
    RandomType, ExpectedPHex, ExpectedQHex, ExpectedGHex: string;
    KeyGenPrivateSeedHex, ExpectedXHex, ExpectedYHex: string;
    SignMessageBytes: TCryptoLibGenericArray<Byte>;
  end;

  TDsaParametersSmokeCase = record
    L, N: Int32;
    RandomHexChunks: TCryptoLibStringArray;
  end;

  /// DSA test vectors: FIPS 186-2/186-3 corpora plus small inline smoke fixtures.
  TDsaVectors = class sealed
  strict private
    class var
      FFips1863Rows: TCryptoLibGenericArray<TDsaFips1863Row>;
      FFips1862Cases: TCryptoLibGenericArray<TDsaFips1862GoldenCase>;
      FTestDsa512GenCase: TDsa512GenCase;
      FDsa2ParametersCase: TDsa2ParametersCase;
      FParametersSmokeCase: TDsaParametersSmokeCase;
      FFips1863Table: TCsvVectorTable;

    class function GetCsvField(const ARow: TCsvRow; const AName: string): string; static;
    class function Fips1863FromCsv(const ARow: TCsvRow): TDsaFips1863Row; static;
    class function ParseParamGenExpected(const AObj: TJsonVectorObject)
      : TDsaParamGenExpected; static;
    class function ParseFips1862Case(const AObj: TJsonVectorObject)
      : TDsaFips1862GoldenCase; static;
    class procedure LoadSmallFixtures; static;
  public
    class function GetFips1863Rows: TCryptoLibGenericArray<TDsaFips1863Row>; static;
    class function GetFips1862GoldenCases
      : TCryptoLibGenericArray<TDsaFips1862GoldenCase>; static;
    class function GetTestDsa512GenCase: TDsa512GenCase; static;
    class function GetDsa2ParametersCase: TDsa2ParametersCase; static;
    class function GetParametersSmokeCase: TDsaParametersSmokeCase; static;
    class function BuildParameters(const APHex, AQHex, AGHex: string): IDsaParameters; static;
    class function BuildParametersFromFips1863Row(const ARow: TDsaFips1863Row)
      : IDsaParameters; static;
    class function BuildPrivateKey(const AXHex: string; const AParams: IDsaParameters)
      : IDsaPrivateKeyParameters; static;
    class function BuildPublicKey(const AYHex: string; const AParams: IDsaParameters)
      : IDsaPublicKeyParameters; static;
    class function BuildDigestSigner(const ADigestName: string): IDsaDigestSigner; static;
    class function DecodeHexField(const AHex: string): TCryptoLibByteArray; static;
    class constructor Create;
  end;

  TEcdsaCurveType = (Fp, F2m);

  TEcdsaCurveRow = record
    CurveId: string;
    CurveType: TEcdsaCurveType;
    FieldPrime: string;
    AHex, BHex, CurveOrderHex, CofactorHex, GHex, N: string;
    M, K: Int32;
  end;

  TEcdsaVectorRow = record
    VectorId, CurveId, Algorithm: string;
    MessageEncoding, MessageText: string;
    PrivateD, PublicQHex, KDecimal: string;
    ExpectedR, ExpectedS, ExpectedSigDerHex: string;
  end;

  TEdwardsRegressionRow = record
    PubB64, PrivB64, MsgB64, SigB64, Comment: string;
  end;

  /// <summary>
  /// Ed25519 infinite-loop regression vectors loaded from external CSV.
  /// </summary>
  TEd25519RegressionVectors = class sealed
  strict private
    class var
      FAllRows: TCryptoLibGenericArray<TEdwardsRegressionRow>;
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TEdwardsRegressionRow; static;
  public
    class function GetRows: TCryptoLibGenericArray<TEdwardsRegressionRow>; static;
    class constructor Create;
  end;

  /// <summary>
  /// Ed448 infinite-loop regression vectors loaded from external CSV.
  /// </summary>
  TEd448RegressionVectors = class sealed
  strict private
    class var
      FAllRows: TCryptoLibGenericArray<TEdwardsRegressionRow>;
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TEdwardsRegressionRow; static;
  public
    class function GetRows: TCryptoLibGenericArray<TEdwardsRegressionRow>; static;
    class constructor Create;
  end;

  /// <summary>
  /// X9.62 239-bit ECDSA test curves and vectors loaded from external JSON.
  /// </summary>
  TEcdsaVectors = class sealed
  strict private
    class var
      FCurves: TCryptoLibGenericArray<TEcdsaCurveRow>;
      FVectors: TCryptoLibGenericArray<TEcdsaVectorRow>;

    class function CurveFromJson(const AObj: TJsonVectorObject): TEcdsaCurveRow; static;
    class function VectorFromJson(const AObj: TJsonVectorObject): TEcdsaVectorRow; static;
    class function FindCurveIndex(const ACurveId: string): Integer; static;
  public
    class function GetCurve(const ACurveId: string): TEcdsaCurveRow; static;
    class function GetVectors: TCryptoLibGenericArray<TEcdsaVectorRow>; static;
    class function GetVectorById(const AVectorId: string): TEcdsaVectorRow; static;
    class function BuildDomainParameters(const ACurve: TEcdsaCurveRow)
      : IECDomainParameters; static;
    class function BuildPrivateKey(const AVector: TEcdsaVectorRow;
      const ASpec: IECDomainParameters): IECPrivateKeyParameters; static;
    class function BuildPublicKey(const AVector: TEcdsaVectorRow;
      const ASpec: IECDomainParameters): IECPublicKeyParameters; static;
    class function BuildFixedK(const AKDecimal: string): ISecureRandom; static;
    class function DecodeMessage(const AVector: TEcdsaVectorRow): TCryptoLibByteArray; static;
    class function DecodeSigDer(const AVector: TEcdsaVectorRow): TCryptoLibByteArray; static;
    class constructor Create;
  end;

implementation

uses
  ClpDSADigestSigner,
  ClpDsaSigner,
  ClpIDsaSigner;

{ TPssVectors }

class function TPssVectors.RowFromCsv(const ARow: TCsvRow): TPssVectorRow;
begin
  Result.ExampleId := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'ExampleId');
  Result.SubCase := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'SubCase');
  Result.TestId := StrToIntDef(TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'TestId'), 0);
  Result.Modulus := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'Modulus');
  Result.PubExp := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'PubExp');
  Result.PrivExp := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'PrivExp');
  Result.P := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'P');
  Result.Q := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'Q');
  Result.DP := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'DP');
  Result.DQ := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'DQ');
  Result.QInv := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'QInv');
  Result.MsgHex := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'MsgHex');
  Result.SaltHex := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'SaltHex');
  Result.SigHex := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'SigHex');
end;

class function TPssVectors.GetRows: TCryptoLibGenericArray<TPssVectorRow>;
begin
  Result := FAllRows;
end;

class function TPssVectors.GetRowByTestId(const ATestId: Integer): TPssVectorRow;
var
  LI: Integer;
begin
  for LI := 0 to High(FAllRows) do
  begin
    if FAllRows[LI].TestId = ATestId then
      Exit(FAllRows[LI]);
  end;
  raise Exception.CreateFmt('Unknown PSS test id: %d', [ATestId]);
end;

class function TPssVectors.GetExampleKeyRow(const AExampleId: string): TPssVectorRow;
var
  LI: Integer;
begin
  for LI := 0 to High(FAllRows) do
  begin
    if SameText(FAllRows[LI].ExampleId, AExampleId) then
      Exit(FAllRows[LI]);
  end;
  raise Exception.CreateFmt('Unknown PSS example id: %s', [AExampleId]);
end;

class function TPssVectors.CreatePublicKey(const ARow: TPssVectorRow): IRsaKeyParameters;
var
  LRecord: TRsaCrtHexRecord;
begin
  LRecord.Modulus := ARow.Modulus;
  LRecord.PubExp := ARow.PubExp;
  Result := TTestKeyBuilders.CreateRsaPublicFromHexRecord(LRecord);
end;

class function TPssVectors.CreatePrivateCrtKey(const ARow: TPssVectorRow)
  : IRsaPrivateCrtKeyParameters;
var
  LRecord: TRsaCrtHexRecord;
begin
  LRecord.Modulus := ARow.Modulus;
  LRecord.PubExp := ARow.PubExp;
  LRecord.PrivExp := ARow.PrivExp;
  LRecord.P := ARow.P;
  LRecord.Q := ARow.Q;
  LRecord.DP := ARow.DP;
  LRecord.DQ := ARow.DQ;
  LRecord.QInv := ARow.QInv;
  Result := TTestKeyBuilders.CreateRsaPrivateCrtFromHexRecord(LRecord);
end;

class function TPssVectors.DecodeMsg(const ARow: TPssVectorRow): TCryptoLibByteArray;
begin
  Result := THexEncoder.Decode(ARow.MsgHex);
end;

class function TPssVectors.DecodeSalt(const ARow: TPssVectorRow): TCryptoLibByteArray;
begin
  Result := THexEncoder.Decode(ARow.SaltHex);
end;

class function TPssVectors.DecodeSig(const ARow: TPssVectorRow): TCryptoLibByteArray;
begin
  Result := THexEncoder.Decode(ARow.SigHex);
end;

class constructor TPssVectors.Create;
var
  LI: Integer;
begin
  FTable := TCsvVectorLoaderBase.LoadTable('Crypto/Rsa/Pss/Manifest.csv');
  SetLength(FAllRows, Length(FTable.Rows));
  for LI := 0 to High(FTable.Rows) do
    FAllRows[LI] := RowFromCsv(FTable.Rows[LI]);
end;

{ TOaepVectors }

class function TOaepVectors.KeySetFromCsv(const ARow: TCsvRow): TOaepKeySetRow;
begin
  Result.KeySetId := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'KeySetId');
  Result.KeyType := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'KeyType');
  Result.Modulus := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'Modulus');
  Result.PubExp := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'PubExp');
  Result.PrivExp := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'PrivExp');
  Result.P := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'P');
  Result.Q := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'Q');
  Result.DP := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'DP');
  Result.DQ := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'DQ');
  Result.QInv := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'QInv');
  Result.PubDerHex := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'PubDerHex');
  Result.PrivDerHex := TCsvVectorLoaderBase.GetFieldTrimmed(FKeySetTable, ARow, 'PrivDerHex');
end;

class function TOaepVectors.ManifestFromCsv(const ARow: TCsvRow): TOaepVectorRow;
begin
  Result.VectorId := TCsvVectorLoaderBase.GetFieldTrimmed(FManifestTable, ARow, 'VectorId');
  Result.KeySetId := TCsvVectorLoaderBase.GetFieldTrimmed(FManifestTable, ARow, 'KeySetId');
  Result.VectorNo := TCsvVectorLoaderBase.GetFieldTrimmed(FManifestTable, ARow, 'VectorNo');
  Result.SeedHex := TCsvVectorLoaderBase.GetFieldTrimmed(FManifestTable, ARow, 'SeedHex');
  Result.SeedSource := TCsvVectorLoaderBase.GetFieldTrimmed(FManifestTable, ARow, 'SeedSource');
  Result.InputHex := TCsvVectorLoaderBase.GetFieldTrimmed(FManifestTable, ARow, 'InputHex');
  Result.OutputHex := TCsvVectorLoaderBase.GetFieldTrimmed(FManifestTable, ARow, 'OutputHex');
  Result.OaepDigest := TCsvVectorLoaderBase.GetFieldTrimmed(FManifestTable, ARow, 'OaepDigest');
  Result.OaepMgf := TCsvVectorLoaderBase.GetFieldTrimmed(FManifestTable, ARow, 'OaepMgf');
end;

class function TOaepVectors.ToCrtRecord(const AKeySet: TOaepKeySetRow): TRsaCrtHexRecord;
begin
  Result.Modulus := AKeySet.Modulus;
  Result.PubExp := AKeySet.PubExp;
  Result.PrivExp := AKeySet.PrivExp;
  Result.P := AKeySet.P;
  Result.Q := AKeySet.Q;
  Result.DP := AKeySet.DP;
  Result.DQ := AKeySet.DQ;
  Result.QInv := AKeySet.QInv;
end;

class function TOaepVectors.FindKeySetIndex(const AKeySetId: string): Integer;
begin
  Result := TCsvVectorLoaderBase.FindRowIndex(FKeySetTable, 'KeySetId', AKeySetId,
    'Unknown OAEP key set: %s');
end;

class function TOaepVectors.GetKeySet(const AKeySetId: string): TOaepKeySetRow;
begin
  Result := FKeySets[FindKeySetIndex(AKeySetId)];
end;

class function TOaepVectors.GetManifestRows: TCryptoLibGenericArray<TOaepVectorRow>;
begin
  Result := FManifestRows;
end;

class function TOaepVectors.GetManifestRowsByKeySet(const AKeySetId: string)
  : TCryptoLibGenericArray<TOaepVectorRow>;
var
  LI, LCount: Integer;
begin
  LCount := 0;
  for LI := 0 to High(FManifestRows) do
  begin
    if SameText(FManifestRows[LI].KeySetId, AKeySetId) then
      Inc(LCount);
  end;
  SetLength(Result, LCount);
  LCount := 0;
  for LI := 0 to High(FManifestRows) do
  begin
    if SameText(FManifestRows[LI].KeySetId, AKeySetId) then
    begin
      Result[LCount] := FManifestRows[LI];
      Inc(LCount);
    end;
  end;
end;

class function TOaepVectors.CreatePublicKey(const AKeySet: TOaepKeySetRow): IAsymmetricKeyParameter;
begin
  if SameText(AKeySet.KeyType, 'Der') then
    Result := TPublicKeyFactory.CreateKey(DecodeHexField(AKeySet.PubDerHex))
  else
    Result := TTestKeyBuilders.CreateRsaPublicFromDecodedHex(ToCrtRecord(AKeySet));
end;

class function TOaepVectors.CreatePrivateKey(const AKeySet: TOaepKeySetRow): IAsymmetricKeyParameter;
begin
  if SameText(AKeySet.KeyType, 'Der') then
    Result := TPrivateKeyFactory.CreateKey(DecodeHexField(AKeySet.PrivDerHex))
  else
    Result := TTestKeyBuilders.CreateRsaPrivateCrtFromDecodedHex(ToCrtRecord(AKeySet));
end;

class function TOaepVectors.DecodeHexField(const AHex: string): TCryptoLibByteArray;
begin
  Result := THexEncoder.Decode(AHex);
end;

class function TOaepVectors.ResolveSeedBytes(const AVector: TOaepVectorRow;
  const AKeySet: TOaepKeySetRow): TCryptoLibByteArray;
begin
  if SameText(AVector.SeedSource, 'PubKeyDer') then
    Result := DecodeHexField(AKeySet.PubDerHex)
  else
    Result := THexEncoder.Decode(AVector.SeedHex);
end;

class constructor TOaepVectors.Create;
var
  LI: Integer;
begin
  FKeySetTable := TCsvVectorLoaderBase.LoadTable('Crypto/Rsa/Oaep/KeySets.csv');
  SetLength(FKeySets, Length(FKeySetTable.Rows));
  for LI := 0 to High(FKeySetTable.Rows) do
    FKeySets[LI] := KeySetFromCsv(FKeySetTable.Rows[LI]);

  FManifestTable := TCsvVectorLoaderBase.LoadTable('Crypto/Rsa/Oaep/Manifest.csv');
  SetLength(FManifestRows, Length(FManifestTable.Rows));
  for LI := 0 to High(FManifestTable.Rows) do
    FManifestRows[LI] := ManifestFromCsv(FManifestTable.Rows[LI]);
end;

{ TIso9796Vectors }

class function TIso9796Vectors.GetField(const ARow: TCsvRow; const AName: string): string;
begin
  Result := Trim(TCsvVectorParser.GetField(ARow, FTable.Header, AName));
end;

class function TIso9796Vectors.RowFromCsv(const ARow: TCsvRow): TIso9796VectorRow;
begin
  Result.TestId := GetField(ARow, 'TestId');
  Result.ModulusHex := GetField(ARow, 'ModulusHex');
  Result.PubExpHex := GetField(ARow, 'PubExpHex');
  Result.PriExpHex := GetField(ARow, 'PriExpHex');
  Result.MessageHex := GetField(ARow, 'MessageHex');
  Result.SignatureHex := GetField(ARow, 'SignatureHex');
  Result.SignSubtrahendHex := GetField(ARow, 'SignSubtrahendHex');
  Result.PadBits := StrToIntDef(GetField(ARow, 'PadBits'), 0);
  Result.SigCompareOffset := StrToIntDef(GetField(ARow, 'SigCompareOffset'), 0);
  Result.MsgCompareOffset := StrToIntDef(GetField(ARow, 'MsgCompareOffset'), 0);
  Result.GenerationCompare := GetField(ARow, 'GenerationCompare');
end;

class function TIso9796Vectors.ComputeExpectedSignature(
  const ARow: TIso9796VectorRow): TCryptoLibByteArray;
var
  LMod: TBigInteger;
begin
  if ARow.SignSubtrahendHex <> '' then
  begin
    LMod := TBigInteger.Create(ARow.ModulusHex, 16);
    Result := LMod.Subtract(TBigInteger.Create(ARow.SignSubtrahendHex, 16)).ToByteArray();
  end
  else
    Result := TBigInteger.Create(ARow.SignatureHex, 16).ToByteArray();
end;

class function TIso9796Vectors.GetRows: TCryptoLibGenericArray<TIso9796VectorRow>;
begin
  Result := FAllRows;
end;

class function TIso9796Vectors.GetRow(const ATestId: string): TIso9796VectorRow;
begin
  Result := RowFromCsv(TCsvVectorParser.FindRowByField(FTable, 'TestId', ATestId));
end;

class constructor TIso9796Vectors.Create;
var
  LI: Integer;
begin
  FTable := TCsvVectorLoaderBase.LoadTable('Crypto/Rsa/Iso9796.csv');
  SetLength(FAllRows, Length(FTable.Rows));
  for LI := 0 to High(FTable.Rows) do
    FAllRows[LI] := RowFromCsv(FTable.Rows[LI]);
end;

{ TDsaVectors }

class function TDsaVectors.GetCsvField(const ARow: TCsvRow; const AName: string): string;
begin
  Result := Trim(TCsvVectorParser.GetField(ARow, FFips1863Table.Header, AName));
end;

class function TDsaVectors.Fips1863FromCsv(const ARow: TCsvRow): TDsaFips1863Row;
begin
  Result.DigestName := GetCsvField(ARow, 'DigestName');
  Result.PHex := GetCsvField(ARow, 'P');
  Result.QHex := GetCsvField(ARow, 'Q');
  Result.GHex := GetCsvField(ARow, 'G');
  Result.XHex := GetCsvField(ARow, 'X');
  Result.YHex := GetCsvField(ARow, 'Y');
  Result.KBigInt := GetCsvField(ARow, 'KBigInt');
  Result.KPadHex := GetCsvField(ARow, 'KPadHex');
  Result.MessageHex := GetCsvField(ARow, 'MessageHex');
  Result.ExpectedRHex := GetCsvField(ARow, 'ExpectedR');
  Result.ExpectedSHex := GetCsvField(ARow, 'ExpectedS');
end;

class function TDsaVectors.ParseParamGenExpected(const AObj: TJsonVectorObject)
  : TDsaParamGenExpected;
var
  LExpected: TJsonVectorObject;
begin
  LExpected := AObj.GetNestedObject('expected');
  try
    Result.Counter := LExpected.GetInt('counter');
    Result.PHex := LExpected.GetString('p');
    Result.QHex := LExpected.GetString('q');
    Result.GHex := LExpected.GetString('g');
  finally
    LExpected.Free;
  end;
end;

class function TDsaVectors.ParseFips1862Case(const AObj: TJsonVectorObject)
  : TDsaFips1862GoldenCase;
var
  LParamGen, LKeyGen, LSign: TJsonVectorObject;
begin
  Result.TestId := AObj.GetString('testId');
  LParamGen := AObj.GetNestedObject('paramGen');
  try
    if LParamGen.IsNullField('digest') then
      Result.ParamGen.DigestName := ''
    else
      Result.ParamGen.DigestName := LParamGen.GetString('digest');
    Result.ParamGen.L := LParamGen.GetInt('L');
    Result.ParamGen.N := LParamGen.GetInt('N');
    Result.ParamGen.Certainty := LParamGen.GetInt('certainty');
    Result.ParamGen.SeedHex := LParamGen.GetString('seedHex');
    Result.ParamGen.RandomType := LParamGen.GetString('randomType');
    Result.ParamGen.Expected := ParseParamGenExpected(LParamGen);
  finally
    LParamGen.Free;
  end;

  LKeyGen := AObj.GetNestedObject('keyGen');
  try
    Result.KeyGen.RandomType := LKeyGen.GetString('randomType');
    Result.KeyGen.PrivateSeedHex := LKeyGen.GetString('privateSeedHex');
    Result.KeyGen.ExpectedXHex := LKeyGen.GetString('expectedX');
    Result.KeyGen.ExpectedYHex := LKeyGen.GetString('expectedY');
  finally
    LKeyGen.Free;
  end;

  LSign := AObj.GetNestedObject('sign');
  try
    Result.Sign.KBigInt := LSign.GetString('kBigInt');
    Result.Sign.KPadHex := LSign.GetString('kPadHex');
    Result.Sign.MessageHex := LSign.GetString('messageHex');
    Result.Sign.ExpectedRHex := LSign.GetString('expectedR');
    Result.Sign.ExpectedSHex := LSign.GetString('expectedS');
  finally
    LSign.Free;
  end;
end;

class procedure TDsaVectors.LoadSmallFixtures;
begin
  FTestDsa512GenCase.L := 512;
  FTestDsa512GenCase.N := 80;
  FTestDsa512GenCase.Certainty := 80;
  FTestDsa512GenCase.ExpectedCounter := 105;
  FTestDsa512GenCase.ExpectedPHex :=
    '8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291';
  FTestDsa512GenCase.ExpectedQHex := 'c773218c737ec8ee993b4f2ded30f48edace915f';
  FTestDsa512GenCase.KeyGenPadHex := '01020304';
  FTestDsa512GenCase.MessageDecimal := '968236873715988614170569073515315707566766479517';
  FTestDsa512GenCase.ExpectedR := '68076202252361894315274692543577577550894681403';
  FTestDsa512GenCase.ExpectedS := '1089214853334067536215539335472893651470583479365';
  SetLength(FTestDsa512GenCase.ParamGenRandom, 2);
  FTestDsa512GenCase.ParamGenRandom[0] := 'D5014E4B60EF2BA8B6211B4062BA3224E0427DD3';
  FTestDsa512GenCase.ParamGenRandom[1] :=
    '345E8D05C075C3A508DF729A1685690E68FCFB8C8117847E89063BCA1F85D968FD281540B6E13BD1AF989A1FBF17E06462BF511F9D0B140FB48AC1B1BAA5BDED';
  SetLength(FTestDsa512GenCase.KeyGenRandom, 2);
  FTestDsa512GenCase.KeyGenRandom[0] := 'B5014E4B60EF2BA8B6211B4062BA3224E0427DD3';
  FTestDsa512GenCase.KeyGenRandom[1] := 'B5014E4B60EF2BA8B6211B4062BA3224E0427DD3';

  FDsa2ParametersCase.SeedHex :=
    '4783081972865EA95D43318AB2EAF9C61A2FC7BBF1B772A09017BDF5A58F4FF0';
  FDsa2ParametersCase.DigestName := 'SHA-256';
  FDsa2ParametersCase.L := 2048;
  FDsa2ParametersCase.N := 256;
  FDsa2ParametersCase.Certainty := 80;
  FDsa2ParametersCase.RandomType := 'DSATestSecureRandom';
  FDsa2ParametersCase.ExpectedPHex :=
    'F56C2A7D366E3EBDEAA1891FD2A0D099436438A673FED4D75F594959CFFEBCA7' +
    'BE0FC72E4FE67D91D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C' +
    '69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A25909132627F51A0C' +
    '866877E672E555342BDF9355347DBD43B47156B2C20BAD9D2B071BC2FDCF9757' +
    'F75C168C5D9FC43131BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A' +
    'EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCDF00E48F2E8356BDB' +
    '59D86114028F67B8E07B127744778AFF1CF1399A4D679D92FDE7D941C5C85C5D' +
    '7BFF91BA69F9489D531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75';
  FDsa2ParametersCase.ExpectedQHex := 'C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467';
  FDsa2ParametersCase.ExpectedGHex :=
    '8DC6CC814CAE4A1C05A3E186A6FE27EABA8CDB133FDCE14A963A92E809790CBA' +
    '096EAA26140550C129FA2B98C16E84236AA33BF919CD6F587E048C52666576DB' +
    '6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2513EA6AA0B8D0F72' +
    'FED73CA37DF240DB57BBB27431D618697B9E771B0B301D5DF05955425061A30D' +
    'C6D33BB6D2A32BD0A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403' +
    '45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8FA39D43D704B6927' +
    'E0B2F916304E86FB6A1B487F07D8139E428BB096C6D67A76EC0B8D4EF274B8A2' +
    'CF556D279AD267CCEF5AF477AFED029F485B5597739F5D0240F67C2D948A6279';
  FDsa2ParametersCase.KeyGenPrivateSeedHex :=
    '0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C';
  FDsa2ParametersCase.ExpectedXHex :=
    '0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C';
  FDsa2ParametersCase.ExpectedYHex :=
    '2828003D7C747199143C370FDD07A2861524514ACC57F63F80C38C2087C6B795' +
    'B62DE1C224BF8D1D1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA' +
    'CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500C611957DBF5ED354' +
    '90714A42811FDCDEB19AF2AB30BEADFF2907931CEE7F3B55532CFFAEB371F84F' +
    '01347630EB227A419B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF' +
    '41566E26FAEE475137EC781A0DC088A26C8804A98C23140E7C936281864B9957' +
    '1EE95C416AA38CEEBB41FDBFF1EB1D1DC97B63CE1355257627C8B0FD840DDB20' +
    'ED35BE92F08C49AEA5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B';
  FDsa2ParametersCase.SignMessageBytes := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 0);

  FParametersSmokeCase.L := 512;
  FParametersSmokeCase.N := 20;
  SetLength(FParametersSmokeCase.RandomHexChunks, 4);
  FParametersSmokeCase.RandomHexChunks[0] := 'D5014E4B60EF2BA8B6211B4062BA3224E0427DD3';
  FParametersSmokeCase.RandomHexChunks[1] :=
    '345E8D05C075C3A508DF729A1685690E68FCFB8C8117847E89063BCA1F85D968FD281540B6E13BD1AF989A1FBF17E06462BF511F9D0B140FB48AC1B1BAA5BDED';
  FParametersSmokeCase.RandomHexChunks[2] := 'D5014E4B60EF2BA8B6211B4062BA3224E0427DD3';
  FParametersSmokeCase.RandomHexChunks[3] :=
    '345E8D05C075C3A508DF729A1685690E68FCFB8C8117847E89063BCA1F85D968FD281540B6E13BD1AF989A1FBF17E06462BF511F9D0B140FB48AC1B1BAA5BDED';
end;

class function TDsaVectors.GetFips1863Rows: TCryptoLibGenericArray<TDsaFips1863Row>;
begin
  Result := FFips1863Rows;
end;

class function TDsaVectors.GetFips1862GoldenCases
  : TCryptoLibGenericArray<TDsaFips1862GoldenCase>;
begin
  Result := FFips1862Cases;
end;

class function TDsaVectors.GetTestDsa512GenCase: TDsa512GenCase;
begin
  Result := FTestDsa512GenCase;
end;

class function TDsaVectors.GetDsa2ParametersCase: TDsa2ParametersCase;
begin
  Result := FDsa2ParametersCase;
end;

class function TDsaVectors.GetParametersSmokeCase: TDsaParametersSmokeCase;
begin
  Result := FParametersSmokeCase;
end;

class function TDsaVectors.BuildParameters(const APHex, AQHex, AGHex: string)
  : IDsaParameters;
begin
  Result := TDsaParameters.Create(
    TBigInteger.Create(APHex, 16),
    TBigInteger.Create(AQHex, 16),
    TBigInteger.Create(AGHex, 16));
end;

class function TDsaVectors.BuildParametersFromFips1863Row(const ARow: TDsaFips1863Row)
  : IDsaParameters;
begin
  Result := BuildParameters(ARow.PHex, ARow.QHex, ARow.GHex);
end;

class function TDsaVectors.BuildPrivateKey(const AXHex: string;
  const AParams: IDsaParameters): IDsaPrivateKeyParameters;
begin
  Result := TDsaPrivateKeyParameters.Create(TBigInteger.Create(AXHex, 16), AParams);
end;

class function TDsaVectors.BuildPublicKey(const AYHex: string;
  const AParams: IDsaParameters): IDsaPublicKeyParameters;
begin
  Result := TDsaPublicKeyParameters.Create(TBigInteger.Create(AYHex, 16), AParams);
end;

class function TDsaVectors.BuildDigestSigner(const ADigestName: string): IDsaDigestSigner;
begin
  Result := TDSADigestSigner.Create(TDSASigner.Create() as IDSASigner,
    TDigestUtilities.GetDigest(ADigestName));
end;

class function TDsaVectors.DecodeHexField(const AHex: string): TCryptoLibByteArray;
begin
  Result := THexEncoder.Decode(AHex);
end;

class constructor TDsaVectors.Create;
var
  LI: Integer;
  LDoc: TJsonVectorDocument;
  LCases: TCryptoLibGenericArray<TJsonVectorObject>;
begin
  FFips1863Table := TCsvVectorLoaderBase.LoadTable('Crypto/Dsa/Fips1863Sha3.csv');
  SetLength(FFips1863Rows, Length(FFips1863Table.Rows));
  for LI := 0 to High(FFips1863Table.Rows) do
    FFips1863Rows[LI] := Fips1863FromCsv(FFips1863Table.Rows[LI]);

  LDoc := TJsonVectorDocument.LoadFile('Crypto/Dsa/Fips1862Golden.json');
  try
    LCases := LDoc.Root.GetObjectArray('cases');
    try
      SetLength(FFips1862Cases, Length(LCases));
      for LI := 0 to High(LCases) do
        FFips1862Cases[LI] := ParseFips1862Case(LCases[LI]);
    finally
      TJsonVectorObject.FreeOwnedArray(LCases);
    end;
  finally
    LDoc.Free;
  end;

  LoadSmallFixtures;
end;

{ TEd25519RegressionVectors }

class function TEd25519RegressionVectors.RowFromCsv(const ARow: TCsvRow)
  : TEdwardsRegressionRow;
begin
  Result.PubB64 := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'PubB64');
  Result.PrivB64 := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'PrivB64');
  Result.MsgB64 := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'MsgB64');
  Result.SigB64 := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'SigB64');
  Result.Comment := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'Comment');
end;

class function TEd25519RegressionVectors.GetRows
  : TCryptoLibGenericArray<TEdwardsRegressionRow>;
begin
  Result := FAllRows;
end;

class constructor TEd25519RegressionVectors.Create;
var
  LI: Integer;
begin
  FTable := TCsvVectorLoaderBase.LoadTable('Crypto/Ed25519/Regression.csv');
  SetLength(FAllRows, Length(FTable.Rows));
  for LI := 0 to High(FTable.Rows) do
    FAllRows[LI] := RowFromCsv(FTable.Rows[LI]);
end;

{ TEd448RegressionVectors }

class function TEd448RegressionVectors.RowFromCsv(const ARow: TCsvRow)
  : TEdwardsRegressionRow;
begin
  Result.PubB64 := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'PubB64');
  Result.PrivB64 := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'PrivB64');
  Result.MsgB64 := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'MsgB64');
  Result.SigB64 := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'SigB64');
  Result.Comment := TCsvVectorLoaderBase.GetFieldTrimmed(FTable, ARow, 'Comment');
end;

class function TEd448RegressionVectors.GetRows
  : TCryptoLibGenericArray<TEdwardsRegressionRow>;
begin
  Result := FAllRows;
end;

class constructor TEd448RegressionVectors.Create;
var
  LI: Integer;
begin
  FTable := TCsvVectorLoaderBase.LoadTable('Crypto/Ed448/Regression.csv');
  SetLength(FAllRows, Length(FTable.Rows));
  for LI := 0 to High(FTable.Rows) do
    FAllRows[LI] := RowFromCsv(FTable.Rows[LI]);
end;

{ TEcdsaVectors }

class function TEcdsaVectors.CurveFromJson(const AObj: TJsonVectorObject)
  : TEcdsaCurveRow;
begin
  Result.CurveId := AObj.GetString('curveId');
  if SameText(AObj.GetString('curveType'), 'Fp') then
    Result.CurveType := TEcdsaCurveType.Fp
  else
    Result.CurveType := TEcdsaCurveType.F2m;
  Result.FieldPrime := AObj.GetString('fieldPrime');
  Result.AHex := AObj.GetString('a');
  Result.BHex := AObj.GetString('b');
  Result.CurveOrderHex := AObj.GetString('curveOrder');
  Result.CofactorHex := AObj.GetString('cofactor');
  Result.GHex := AObj.GetString('gHex');
  Result.N := AObj.GetString('n');
  Result.M := AObj.GetInt('m');
  Result.K := AObj.GetInt('k');
end;

class function TEcdsaVectors.VectorFromJson(const AObj: TJsonVectorObject)
  : TEcdsaVectorRow;
begin
  Result.VectorId := AObj.GetString('vectorId');
  Result.CurveId := AObj.GetString('curveId');
  Result.Algorithm := AObj.GetString('algorithm');
  Result.MessageEncoding := AObj.GetString('messageEncoding');
  Result.MessageText := AObj.GetString('messageText');
  Result.PrivateD := AObj.GetString('privateD');
  Result.PublicQHex := AObj.GetString('publicQHex');
  Result.KDecimal := AObj.GetString('kDecimal');
  Result.ExpectedR := AObj.GetString('expectedR');
  Result.ExpectedS := AObj.GetString('expectedS');
  Result.ExpectedSigDerHex := AObj.GetString('expectedSigDerHex');
end;

class function TEcdsaVectors.FindCurveIndex(const ACurveId: string): Integer;
var
  LI: Integer;
begin
  for LI := 0 to High(FCurves) do
  begin
    if SameText(FCurves[LI].CurveId, ACurveId) then
      Exit(LI);
  end;
  raise Exception.CreateFmt('Unknown ECDSA curve id: %s', [ACurveId]);
end;

class function TEcdsaVectors.GetCurve(const ACurveId: string): TEcdsaCurveRow;
begin
  Result := FCurves[FindCurveIndex(ACurveId)];
end;

class function TEcdsaVectors.GetVectors: TCryptoLibGenericArray<TEcdsaVectorRow>;
begin
  Result := FVectors;
end;

class function TEcdsaVectors.GetVectorById(const AVectorId: string): TEcdsaVectorRow;
var
  LI: Integer;
begin
  for LI := 0 to High(FVectors) do
  begin
    if SameText(FVectors[LI].VectorId, AVectorId) then
      Exit(FVectors[LI]);
  end;
  raise Exception.CreateFmt('Unknown ECDSA vector id: %s', [AVectorId]);
end;

class function TEcdsaVectors.BuildDomainParameters(const ACurve: TEcdsaCurveRow)
  : IECDomainParameters;
var
  LCurve: IECCurve;
  LCofactor: TBigInteger;
begin
  if ACurve.CurveType = TEcdsaCurveType.Fp then
  begin
    LCurve := TFpCurve.Create(
      TBigInteger.Create(ACurve.FieldPrime),
      TBigInteger.Create(ACurve.AHex, 16),
      TBigInteger.Create(ACurve.BHex, 16),
      TBigInteger.Create(ACurve.CurveOrderHex, 16),
      TBigInteger.Create(ACurve.CofactorHex));
    Result := TECDomainParameters.Create(LCurve,
      LCurve.DecodePoint(THexEncoder.Decode(ACurve.GHex)),
      TBigInteger.Create(ACurve.N));
  end
  else
  begin
    LCofactor := TBigInteger.Create(ACurve.CofactorHex);
    LCurve := TF2mCurve.Create(ACurve.M, ACurve.K,
      TBigInteger.Create(ACurve.AHex, 16),
      TBigInteger.Create(ACurve.BHex, 16),
      TBigInteger.Create(ACurve.CurveOrderHex, 16),
      LCofactor);
    Result := TECDomainParameters.Create(LCurve,
      LCurve.DecodePoint(THexEncoder.Decode(ACurve.GHex)),
      TBigInteger.Create(ACurve.N),
      LCofactor);
  end;
end;

class function TEcdsaVectors.BuildPrivateKey(const AVector: TEcdsaVectorRow;
  const ASpec: IECDomainParameters): IECPrivateKeyParameters;
begin
  Result := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create(AVector.PrivateD),
    ASpec);
end;

class function TEcdsaVectors.BuildPublicKey(const AVector: TEcdsaVectorRow;
  const ASpec: IECDomainParameters): IECPublicKeyParameters;
begin
  Result := TECPublicKeyParameters.Create('ECDSA',
    ASpec.Curve.DecodePoint(THexEncoder.Decode(AVector.PublicQHex)),
    ASpec);
end;

class function TEcdsaVectors.BuildFixedK(const AKDecimal: string): ISecureRandom;
var
  LKData: TCryptoLibByteArray;
begin
  LKData := TBigInteger.Create(AKDecimal).ToByteArrayUnsigned;
  Result := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(LKData));
end;

class function TEcdsaVectors.DecodeMessage(const AVector: TEcdsaVectorRow)
  : TCryptoLibByteArray;
begin
  if SameText(AVector.MessageEncoding, 'UTF8') then
    Result := TConverters.ConvertStringToBytes(AVector.MessageText, TEncoding.UTF8)
  else
    Result := TConverters.ConvertStringToBytes(AVector.MessageText, TEncoding.ASCII);
end;

class function TEcdsaVectors.DecodeSigDer(const AVector: TEcdsaVectorRow)
  : TCryptoLibByteArray;
begin
  Result := THexEncoder.Decode(AVector.ExpectedSigDerHex);
end;

class constructor TEcdsaVectors.Create;
var
  LCurveDoc, LVectorDoc: TJsonVectorDocument;
  LCurveItems, LVectorItems: TCryptoLibGenericArray<TJsonVectorObject>;
  LI: Integer;
begin
  LCurveDoc := TJsonVectorDocument.LoadFile('Crypto/Ecdsa/Curves.json');
  try
    LCurveItems := LCurveDoc.Root.GetObjectArray('curves');
    try
      SetLength(FCurves, Length(LCurveItems));
      for LI := 0 to High(LCurveItems) do
        FCurves[LI] := CurveFromJson(LCurveItems[LI]);
    finally
      TJsonVectorObject.FreeOwnedArray(LCurveItems);
    end;
  finally
    LCurveDoc.Free;
  end;

  LVectorDoc := TJsonVectorDocument.LoadFile('Crypto/Ecdsa/Vectors.json');
  try
    LVectorItems := LVectorDoc.Root.GetObjectArray('vectors');
    try
      SetLength(FVectors, Length(LVectorItems));
      for LI := 0 to High(LVectorItems) do
        FVectors[LI] := VectorFromJson(LVectorItems[LI]);
    finally
      TJsonVectorObject.FreeOwnedArray(LVectorItems);
    end;
  finally
    LVectorDoc.Free;
  end;
end;

end.
