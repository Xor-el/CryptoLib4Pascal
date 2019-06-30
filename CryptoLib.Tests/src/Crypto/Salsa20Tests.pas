{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Salsa20Tests;

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
  ClpSalsa20Engine,
  ClpISalsa20Engine,
  ClpICipherParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestSalsa20 = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FZeroes: TBytes;
    FSet1v0_0, FSet1v0_192, FSet1v0_256, FSet1v0_448, FSet1v9_0, FSet1v9_192,
      FSet1v9_256, FSet1v9_448, FSet6v0_0, FSet6v0_65472, FSet6v0_65536,
      FSet6v1_0, FSet6v1_65472, FSet6v1_65536, FSalsa12_set1v0_0,
      FSalsa12_set1v0_192, FSalsa12_set1v0_256, FSalsa12_set1v0_448,
      FSalsa8_set1v0_0, FSalsa8_set1v0_192, FSalsa8_set1v0_256,
      FSalsa8_set1v0_448: String;

    procedure Mismatch(const name, expected: String; found: TBytes);
    procedure DoSalsa20Test1(rounds: Int32; const parameters: ICipherParameters;
      const v0, v192, v256, v448: String);

    procedure DoSalsa20Test2(const parameters: ICipherParameters;
      const v0, v65472, v65536: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestSalsa20Test1;
    procedure TestSalsa20Test2;
    procedure TestReInitBug;

  end;

implementation

{ TTestSalsa20 }

procedure TTestSalsa20.SetUp;
begin
  inherited;
  FZeroes := DecodeHex('00000000000000000000000000000000' +
    '00000000000000000000000000000000' + '00000000000000000000000000000000' +
    '00000000000000000000000000000000');

  FSet1v0_0 := '4DFA5E481DA23EA09A31022050859936' +
    'DA52FCEE218005164F267CB65F5CFD7F' + '2B4F97E0FF16924A52DF269515110A07' +
    'F9E460BC65EF95DA58F740B7D1DBB0AA';

  FSet1v0_192 := 'DA9C1581F429E0A00F7D67E23B730676' +
    '783B262E8EB43A25F55FB90B3E753AEF' + '8C6713EC66C51881111593CCB3E8CB8F' +
    '8DE124080501EEEB389C4BCB6977CF95';

  FSet1v0_256 := '7D5789631EB4554400E1E025935DFA7B' +
    '3E9039D61BDC58A8697D36815BF1985C' + 'EFDF7AE112E5BB81E37ECF0616CE7147' +
    'FC08A93A367E08631F23C03B00A8DA2F';

  FSet1v0_448 := 'B375703739DACED4DD4059FD71C3C47F' +
    'C2F9939670FAD4A46066ADCC6A564578' + '3308B90FFB72BE04A6B147CBE38CC0C3' +
    'B9267C296A92A7C69873F9F263BE9703';

  FSet1v9_0 := '0471076057830FB99202291177FBFE5D' +
    '38C888944DF8917CAB82788B91B53D1C' + 'FB06D07A304B18BB763F888A61BB6B75' +
    '5CD58BEC9C4CFB7569CB91862E79C459';

  FSet1v9_192 := 'D1D7E97556426E6CFC21312AE3811425' +
    '9E5A6FB10DACBD88E4354B0472556935' + '2B6DA5ACAFACD5E266F9575C2ED8E6F2' +
    'EFE4B4D36114C3A623DD49F4794F865B';

  FSet1v9_256 := 'AF06FAA82C73291231E1BD916A773DE1' +
    '52FD2126C40A10C3A6EB40F22834B8CC' + '68BD5C6DBD7FC1EC8F34165C517C0B63' +
    '9DB0C60506D3606906B8463AA0D0EC2F';

  FSet1v9_448 := 'AB3216F1216379EFD5EC589510B8FD35' +
    '014D0AA0B613040BAE63ECAB90A9AF79' + '661F8DA2F853A5204B0F8E72E9D9EB4D' +
    'BA5A4690E73A4D25F61EE7295215140C';

  FSet6v0_0 := 'F5FAD53F79F9DF58C4AEA0D0ED9A9601' +
    'F278112CA7180D565B420A48019670EA' + 'F24CE493A86263F677B46ACE1924773D' +
    '2BB25571E1AA8593758FC382B1280B71';

  FSet6v0_65472 := 'B70C50139C63332EF6E77AC54338A407' +
    '9B82BEC9F9A403DFEA821B83F7860791' + '650EF1B2489D0590B1DE772EEDA4E3BC' +
    'D60FA7CE9CD623D9D2FD5758B8653E70';

  FSet6v0_65536 := '81582C65D7562B80AEC2F1A673A9D01C' +
    '9F892A23D4919F6AB47B9154E08E699B' + '4117D7C666477B60F8391481682F5D95' +
    'D96623DBC489D88DAA6956B9F0646B6E';

  FSet6v1_0 := '3944F6DC9F85B128083879FDF190F7DE' +
    'E4053A07BC09896D51D0690BD4DA4AC1' + '062F1E47D3D0716F80A9B4D85E6D6085' +
    'EE06947601C85F1A27A2F76E45A6AA87';

  FSet6v1_65472 := '36E03B4B54B0B2E04D069E690082C8C5' +
    '92DF56E633F5D8C7682A02A65ECD1371' + '8CA4352AACCB0DA20ED6BBBA62E177F2' +
    '10E3560E63BB822C4158CAA806A88C82';

  FSet6v1_65536 := '1B779E7A917C8C26039FFB23CF0EF8E0' +
    '8A1A13B43ACDD9402CF5DF38501098DF' + 'C945A6CC69A6A17367BC03431A86B3ED' +
    '04B0245B56379BF997E25800AD837D7D';

  // Salsa20/12

  FSalsa12_set1v0_0 := 'FC207DBFC76C5E1774961E7A5AAD0906' +
    '9B2225AC1CE0FE7A0CE77003E7E5BDF8' + 'B31AF821000813E6C56B8C1771D6EE70' +
    '39B2FBD0A68E8AD70A3944B677937897';

  FSalsa12_set1v0_192 := '4B62A4881FA1AF9560586510D5527ED4' +
    '8A51ECAFA4DECEEBBDDC10E9918D44AB' + '26B10C0A31ED242F146C72940C6E9C37' +
    '53F641DA84E9F68B4F9E76B6C48CA5AC';

  FSalsa12_set1v0_256 := 'F52383D9DEFB20810325F7AEC9EADE34' +
    'D9D883FEE37E05F74BF40875B2D0BE79' + 'ED8886E5BFF556CEA8D1D9E86B1F68A9' +
    '64598C34F177F8163E271B8D2FEB5996';

  FSalsa12_set1v0_448 := 'A52ED8C37014B10EC0AA8E05B5CEEE12' +
    '3A1017557FB3B15C53E6C5EA8300BF74' + '264A73B5315DC821AD2CAB0F3BB2F152' +
    'BDAEA3AEE97BA04B8E72A7B40DCC6BA4';

  // Salsa20/8

  FSalsa8_set1v0_0 := 'A9C9F888AB552A2D1BBFF9F36BEBEB33' +
    '7A8B4B107C75B63BAE26CB9A235BBA9D' + '784F38BEFC3ADF4CD3E266687EA7B9F0' +
    '9BA650AE81EAC6063AE31FF12218DDC5';

  FSalsa8_set1v0_192 := 'BB5B6BB2CC8B8A0222DCCC1753ED4AEB' +
    '23377ACCBD5D4C0B69A8A03BB115EF71' + '871BC10559080ACA7C68F0DEF32A80DD' +
    'BAF497259BB76A3853A7183B51CC4B9F';

  FSalsa8_set1v0_256 := '4436CDC0BE39559F5E5A6B79FBDB2CAE' +
    '4782910F27FFC2391E05CFC78D601AD8' + 'CD7D87B074169361D997D1BED9729C0D' +
    'EB23418E0646B7997C06AA84E7640CE3';

  FSalsa8_set1v0_448 := 'BEE85903BEA506B05FC04795836FAAAC' +
    '7F93F785D473EB762576D96B4A65FFE4' + '63B34AAE696777FC6351B67C3753B89B' +
    'A6B197BD655D1D9CA86E067F4D770220';

end;

procedure TTestSalsa20.TearDown;
begin
  inherited;

end;

procedure TTestSalsa20.Mismatch(const name, expected: String; found: TBytes);
begin
  Fail(Format('Mismatch on %s, Expected %s, Found %s.',
    [name, expected, EncodeHex(found)]));
end;

procedure TTestSalsa20.DoSalsa20Test1(rounds: Int32;
  const parameters: ICipherParameters; const v0, v192, v256, v448: String);
var
  salsa: ISalsa20Engine;
  buf: TBytes;
  i: Int32;
begin
  salsa := TSalsa20Engine.Create(rounds);
  salsa.Init(true, parameters);
  System.SetLength(buf, 64);
  i := 0;
  while i <> 7 do
  begin
    salsa.ProcessBytes(FZeroes, 0, 64, buf, 0);
    case i of
      0:
        begin
          if not(AreEqual(buf, DecodeHex(v0))) then
          begin
            Mismatch(Format('v0/%d', [rounds]), v0, buf);
          end;
        end;
      3:
        begin
          if not(AreEqual(buf, DecodeHex(v192))) then
          begin
            Mismatch(Format('v192/%d', [rounds]), v192, buf);
          end;
        end;
      4:
        begin
          if not(AreEqual(buf, DecodeHex(v256))) then
          begin
            Mismatch(Format('v256/%d', [rounds]), v256, buf);
          end;
        end
    else
      begin
        // ignore
      end;
    end;
    System.Inc(i);
  end;

  i := 0;
  while i <> 64 do
  begin
    buf[i] := salsa.ReturnByte(FZeroes[i]);
    System.Inc(i);
  end;

  if not(AreEqual(buf, DecodeHex(v448))) then
  begin
    Mismatch(Format('v448/%d', [rounds]), v448, buf);
  end;
end;

procedure TTestSalsa20.DoSalsa20Test2(const parameters: ICipherParameters;
  const v0, v65472, v65536: String);
var
  salsa: ISalsa20Engine;
  buf: TBytes;
  i: Int32;
begin
  salsa := TSalsa20Engine.Create();
  salsa.Init(true, parameters);
  System.SetLength(buf, 64);
  i := 0;
  while i <> 1025 do
  begin
    salsa.ProcessBytes(FZeroes, 0, 64, buf, 0);
    case i of
      0:
        begin
          if not(AreEqual(buf, DecodeHex(v0))) then
          begin
            Mismatch('v0', v0, buf);
          end;
        end;
      1023:
        begin
          if not(AreEqual(buf, DecodeHex(v65472))) then
          begin
            Mismatch('v65472', v65472, buf);
          end;
        end;
      1024:
        begin
          if not(AreEqual(buf, DecodeHex(v65536))) then
          begin
            Mismatch('v65536', v65536, buf);
          end;
        end
    else
      begin
        // ignore
      end;
    end;
    System.Inc(i);
  end;

end;

procedure TTestSalsa20.TestSalsa20Test1;
begin
  DoSalsa20Test1(20, TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex('80000000000000000000000000000000'))
    as IKeyParameter, DecodeHex('0000000000000000')) as IParametersWithIV,
    FSet1v0_0, FSet1v0_192, FSet1v0_256, FSet1v0_448);
  DoSalsa20Test1(20, TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex('00400000000000000000000000000000'))
    as IKeyParameter, DecodeHex('0000000000000000')) as IParametersWithIV,
    FSet1v9_0, FSet1v9_192, FSet1v9_256, FSet1v9_448);

  DoSalsa20Test1(12, TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex('80000000000000000000000000000000'))
    as IKeyParameter, DecodeHex('0000000000000000')), FSalsa12_set1v0_0,
    FSalsa12_set1v0_192, FSalsa12_set1v0_256, FSalsa12_set1v0_448);
  DoSalsa20Test1(8, TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex('80000000000000000000000000000000'))
    as IKeyParameter, DecodeHex('0000000000000000')) as IParametersWithIV,
    FSalsa8_set1v0_0, FSalsa8_set1v0_192, FSalsa8_set1v0_256,
    FSalsa8_set1v0_448);

end;

procedure TTestSalsa20.TestSalsa20Test2;
begin
  DoSalsa20Test2(TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex
    ('0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D'))
    as IKeyParameter, DecodeHex('0D74DB42A91077DE')) as IParametersWithIV,
    FSet6v0_0, FSet6v0_65472, FSet6v0_65536);
  DoSalsa20Test2(TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex
    ('0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12'))
    as IKeyParameter, DecodeHex('167DE44BB21980E7')) as IParametersWithIV,
    FSet6v1_0, FSet6v1_65472, FSet6v1_65536);
end;

procedure TTestSalsa20.TestReInitBug;
var
  key: IKeyParameter;
  parameters: IParametersWithIV;
  salsa: ISalsa20Engine;
begin
  key := TKeyParameter.Create(DecodeHex('80000000000000000000000000000000'));
  parameters := TParametersWithIV.Create(key, DecodeHex('0000000000000000'));

  salsa := TSalsa20Engine.Create();

  salsa.Init(true, parameters);
  try
    salsa.Init(true, key);
    Fail('Salsa20 should throw exception if no IV in Init');

  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSalsa20);
{$ELSE}
  RegisterTest(TTestSalsa20.Suite);
{$ENDIF FPC}

end.
