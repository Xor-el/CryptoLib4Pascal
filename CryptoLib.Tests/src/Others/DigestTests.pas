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

unit DigestTests;

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
  ClpMiscObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpRosstandartObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpIDigest,
  ClpDigestUtilities,
  ClpConverters,
  CsvVectorParser,
  CryptoLibTestBase,
  ClpCryptoLibTypes;

type

  TTestDigest = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FAbcVectors: TCryptoLibMatrixGenericArray<String>;

    procedure DoTest(const AAlgorithm: String);
    procedure DoAbcTest(const AAlgorithm, AHash: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestDigests();

  end;

implementation

{ TTestDigest }

procedure TTestDigest.SetUp;
var
  LContent: string;
  LHeader: TCryptoLibStringArray;
  LRows: TCryptoLibGenericArray<TCsvRow>;
  LI: Integer;
begin
  inherited;
  LContent := LoadTestResource('Crypto/Digest/AbcVectors.csv');
  LHeader := TCsvVectorParser.GetHeader(LContent);
  LRows := TCsvVectorParser.Parse(LContent, True);
  SetLength(FAbcVectors, Length(LRows));
  for LI := 0 to High(LRows) do
    FAbcVectors[LI] := TCryptoLibStringArray.Create(
      TCsvVectorParser.GetField(LRows[LI], LHeader, 'Algorithm'),
      TCsvVectorParser.GetField(LRows[LI], LHeader, 'Digest'));
end;

procedure TTestDigest.TearDown;
begin
  FAbcVectors := nil;
  inherited;
end;

procedure TTestDigest.DoAbcTest(const AAlgorithm, AHash: String);
var
  LAbc, LResult: TBytes;
  LDigest: IDigest;
begin
  LAbc := TBytes.Create($61, $62, $63);

  LDigest := TDigestUtilities.GetDigest(AAlgorithm);

  LDigest.BlockUpdate(LAbc, 0, System.Length(LAbc));
  LResult := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, DecodeHex(AHash))) then
  begin
    Fail(Format('abc result not equal for %s, expected %s actual %s', [AAlgorithm, AHash, EncodeHex(LResult)]));
  end;
end;

procedure TTestDigest.DoTest(const AAlgorithm: String);
var
  LMessage, LResult, LResult2: TBytes;
  LDigest, LD: IDigest;
  LI: Int32;
begin
  LMessage := TConverters.ConvertStringToBytes('hello world', TEncoding.ASCII);

  LDigest := TDigestUtilities.GetDigest(AAlgorithm);

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LResult := TDigestUtilities.DoFinal(LDigest);

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 1 not equal');
  end;

  for LI := 0 to System.Pred(System.Length(LMessage)) do
  begin
    LDigest.Update(LMessage[LI]);
  end;

  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 2 not equal');
  end;

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage) div 2);
  LDigest.BlockUpdate(LMessage, System.Length(LMessage) div 2,
    System.Length(LMessage) - (System.Length(LMessage) div 2));

  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 3 not equal');
  end;

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage) div 2);
  LD := LDigest.Clone();
  LDigest.BlockUpdate(LMessage, System.Length(LMessage) div 2,
    System.Length(LMessage) - (System.Length(LMessage) div 2));

  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 4(a) not equal');
  end;

  LD.BlockUpdate(LMessage, System.Length(LMessage) div 2,
    System.Length(LMessage) - (System.Length(LMessage) div 2));

  LResult2 := TDigestUtilities.DoFinal(LD);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 4(b) not equal');
  end;

  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage) div 2);
  LDigest.Reset();
  LDigest.BlockUpdate(LMessage, 0, System.Length(LMessage) div 2);
  LDigest.BlockUpdate(LMessage, System.Length(LMessage) div 2,
    System.Length(LMessage) - (System.Length(LMessage) div 2));

  LResult2 := TDigestUtilities.DoFinal(LDigest);

  if (not AreEqual(LResult, LResult2)) then
  begin
    Fail('Result object 5 not equal');
  end;

end;

procedure TTestDigest.TestDigests;
var
  LI: Int32;
begin
  for LI := 0 to System.Pred(System.Length(FAbcVectors)) do
  begin
    DoTest(FAbcVectors[LI][0]);

    DoAbcTest(FAbcVectors[LI][0], FAbcVectors[LI][1]);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestDigest);
{$ELSE}
  RegisterTest(TTestDigest.Suite);
{$ENDIF FPC}

end.
