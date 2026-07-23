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

unit GMacTests;

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
  ClpIMac,
  ClpGMac,
  ClpGcmBlockCipher,
  ClpIGcmBlockCipher,
  ClpAesUtilities,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase,
  SymmetricBlockVectors;

type

  TTestGMac = class(TCryptoLibAlgorithmTestCase)
  private
    procedure TestSingleByte(const AMac: IMac; const AName: string;
      const AAd, ATag: TBytes);
    procedure TestMultiByte(const AMac: IMac; const AName: string;
      const AAd, ATag: TBytes);
    procedure CheckMac(const AMac: IMac; const AName: string;
      const ATag: TBytes);
    procedure TestInvalidMacSize(ASize: Int32);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestGMacVectors;
    procedure TestInvalidMacSizes;

  end;

implementation

{ TTestGMac }

procedure TTestGMac.SetUp;
begin
  inherited;
end;

procedure TTestGMac.TearDown;
begin
  inherited;
end;

procedure TTestGMac.TestSingleByte(const AMac: IMac; const AName: string;
  const AAd, ATag: TBytes);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(AAd) - 1 do
  begin
    AMac.Update(AAd[LI]);
  end;
  CheckMac(AMac, AName, ATag);
end;

procedure TTestGMac.TestMultiByte(const AMac: IMac; const AName: string;
  const AAd, ATag: TBytes);
begin
  AMac.BlockUpdate(AAd, 0, System.Length(AAd));
  CheckMac(AMac, AName, ATag);
end;

procedure TTestGMac.CheckMac(const AMac: IMac; const AName: string;
  const ATag: TBytes);
var
  LGeneratedMac: TBytes;
begin
  System.SetLength(LGeneratedMac, AMac.GetMacSize());
  AMac.DoFinal(LGeneratedMac, 0);
  if not AreEqual(ATag, LGeneratedMac) then
  begin
    Fail(Format('Failed %s - expected %s got %s',
      [AName, EncodeHex(ATag), EncodeHex(LGeneratedMac)]));
  end;
end;

procedure TTestGMac.TestInvalidMacSize(ASize: Int32);
var
  LMac: IMac;
begin
  try
    LMac := TGMac.Create(
      TGcmBlockCipher.Create(TAesUtilities.CreateEngine())
        as IGcmBlockCipher,
      ASize) as IMac;
    LMac.Init(
      TParametersWithIV.Create(
        TKeyParameter.Create(TBytes.Create(
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) as IKeyParameter,
        TBytes.Create(
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
      as ICipherParameters);
    Fail(Format('Expected failure for illegal mac size %d', [ASize]));
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TTestGMac.TestGMacVectors;
var
  LRows: TCryptoLibGenericArray<TGmacVectorRow>;
  LI: Int32;
  LRow: TGmacVectorRow;
  LKey, LIv, LAd, LTag: TBytes;
  LMac: IMac;
  LKeyParam: IKeyParameter;
begin
  LRows := TGcmVectors.GetNistGmacRows;
  for LI := 0 to High(LRows) do
  begin
    LRow := LRows[LI];
    LKey := DecodeHex(LRow.Key);
    LIv := DecodeHex(LRow.Iv);
    LAd := DecodeHex(LRow.Aad);
    LTag := DecodeHex(LRow.Tag);

    LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;

    LMac := TGMac.Create(
      TGcmBlockCipher.Create(TAesUtilities.CreateEngine())
        as IGcmBlockCipher,
      System.Length(LTag) * 8) as IMac;
    LMac.Init(TParametersWithIV.Create(LKeyParam, LIv) as ICipherParameters);
    TestSingleByte(LMac, LRow.Name, LAd, LTag);

    LMac := TGMac.Create(
      TGcmBlockCipher.Create(TAesUtilities.CreateEngine())
        as IGcmBlockCipher,
      System.Length(LTag) * 8) as IMac;
    LMac.Init(TParametersWithIV.Create(LKeyParam, LIv) as ICipherParameters);
    TestMultiByte(LMac, LRow.Name, LAd, LTag);
  end;
end;

procedure TTestGMac.TestInvalidMacSizes;
begin
  TestInvalidMacSize(97);
  TestInvalidMacSize(136);
  TestInvalidMacSize(24);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestGMac);
{$ELSE}
  RegisterTest(TTestGMac.Suite);
{$ENDIF FPC}

end.
