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

unit ChaChaTests;

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
  ClpChaChaEngine,
  ClpIChaChaEngine,
  ClpICipherParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// <para>
  /// ChaCha Test
  /// </para>
  /// <para>
  /// Test cases generated using ref version of ChaCha20 in
  /// estreambench-20080905.
  /// </para>
  /// </summary>
  TTestChaCha = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FZeroes: TBytes;
    FSet1v0_0, FSet1v0_192, FSet1v0_256, FSet1v0_448, FSet1v9_0, FSet1v9_192,
      FSet1v9_256, FSet1v9_448, FSet6v0_0, FSet6v0_65472, FSet6v0_65536,
      FSet6v1_0, FSet6v1_65472, FSet6v1_65536, FChaCha12_set1v0_0,
      FChaCha12_set1v0_192, FChaCha12_set1v0_256, FChaCha12_set1v0_448,
      FChaCha8_set1v0_0, FChaCha8_set1v0_192, FChaCha8_set1v0_256,
      FChaCha8_set1v0_448: String;

    procedure Mismatch(const name, expected: String; found: TBytes);
    procedure DoChaChaTest1(rounds: Int32; const parameters: ICipherParameters;
      const v0, v192, v256, v448: String);

    procedure DoChaChaTest2(const parameters: ICipherParameters;
      const v0, v65472, v65536: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestDoChaChaTest1;
    procedure TestDoChaChaTest2;
    procedure TestReInitBug;

  end;

implementation

{ TTestChaCha }

procedure TTestChaCha.SetUp;
begin
  inherited;
  FZeroes := DecodeHex('00000000000000000000000000000000' +
    '00000000000000000000000000000000' + '00000000000000000000000000000000' +
    '00000000000000000000000000000000');

  FSet1v0_0 := 'FBB87FBB8395E05DAA3B1D683C422046' +
    'F913985C2AD9B23CFC06C1D8D04FF213' + 'D44A7A7CDB84929F915420A8A3DC58BF' +
    '0F7ECB4B1F167BB1A5E6153FDAF4493D';

  FSet1v0_192 := 'D9485D55B8B82D792ED1EEA8E93E9BC1' +
    'E2834AD0D9B11F3477F6E106A2F6A5F2' + 'EA8244D5B925B8050EAB038F58D4DF57' +
    '7FAFD1B89359DAE508B2B10CBD6B488E';

  FSet1v0_256 := '08661A35D6F02D3D9ACA8087F421F7C8' +
    'A42579047D6955D937925BA21396DDD4' + '74B1FC4ACCDCAA33025B4BCE817A4FBF' +
    '3E5D07D151D7E6FE04934ED466BA4779';

  FSet1v0_448 := 'A7E16DD38BA48CCB130E5BE9740CE359' +
    'D631E91600F85C8A5D0785A612D1D987' + '90780ACDDC26B69AB106CCF6D866411D' +
    '10637483DBF08CC5591FD8B3C87A3AE0';

  FSet1v9_0 := 'A276339F99316A913885A0A4BE870F06' +
    '91E72B00F1B3F2239F714FE81E88E00C' + 'BBE52B4EBBE1EA15894E29658C4CB145' +
    'E6F89EE4ABB045A78514482CE75AFB7C';

  FSet1v9_192 := '0DFB9BD4F87F68DE54FBC1C6428FDEB0' +
    '63E997BE8490C9B7A4694025D6EBA2B1' + '5FE429DB82A7CAE6AAB22918E8D00449' +
    '6FB6291467B5AE81D4E85E81D8795EBB';

  FSet1v9_256 := '546F5BB315E7F71A46E56D4580F90889' +
    '639A2BA528F757CF3B048738BA141AF3' + 'B31607CB21561BAD94721048930364F4' +
    'B1227CFEB7CDECBA881FB44903550E68';

  FSet1v9_448 := '6F813586E76691305A0CF048C0D8586D' +
    'C89460207D8B230CD172398AA33D19E9' + '2D24883C3A9B0BB7CD8C6B2668DB142E' +
    '37A97948A7A01498A21110297984CD20';

  FSet6v0_0 := '57459975BC46799394788DE80B928387' +
    '862985A269B9E8E77801DE9D874B3F51' + 'AC4610B9F9BEE8CF8CACD8B5AD0BF17D' +
    '3DDF23FD7424887EB3F81405BD498CC3';

  FSet6v0_65472 := 'EF9AEC58ACE7DB427DF012B2B91A0C1E' +
    '8E4759DCE9CDB00A2BD59207357BA06C' + 'E02D327C7719E83D6348A6104B081DB0' +
    '3908E5186986AE41E3AE95298BB7B713';

  FSet6v0_65536 := '17EF5FF454D85ABBBA280F3A94F1D26E' +
    '950C7D5B05C4BB3A78326E0DC5731F83' + '84205C32DB867D1B476CE121A0D7074B' +
    'AA7EE90525D15300F48EC0A6624BD0AF';

  FSet6v1_0 := '92A2508E2C4084567195F2A1005E552B' +
    '4874EC0504A9CD5E4DAF739AB553D2E7' + '83D79C5BA11E0653BEBB5C116651302E' +
    '8D381CB728CA627B0B246E83942A2B99';

  FSet6v1_65472 := 'E1974EC3063F7BD0CBA58B1CE34BC874' +
    '67AAF5759B05EA46682A5D4306E5A76B' + 'D99A448DB8DE73AF97A73F5FBAE2C776' +
    '35040464524CF14D7F08D4CE1220FD84';

  FSet6v1_65536 := 'BE3436141CFD62D12FF7D852F80C1344' +
    '81F152AD0235ECF8CA172C55CA8C031B' + '2E785D773A988CA8D4BDA6FAE0E493AA' +
    '71DCCC4C894D1F106CAC62A9FC0A9607';

  // ChaCha12
  FChaCha12_set1v0_0 := '36CF0D56E9F7FBF287BC5460D95FBA94' +
    'AA6CBF17D74E7C784DDCF7E0E882DDAE' + '3B5A58243EF32B79A04575A8E2C2B73D' +
    'C64A52AA15B9F88305A8F0CA0B5A1A25';

  FChaCha12_set1v0_192 := '83496792AB68FEC75ADB16D3044420A4' +
    'A00A6E9ADC41C3A63DBBF317A8258C85' + 'A9BC08B4F76B413A4837324AEDF8BC2A' +
    '67D53C9AB9E1C5BC5F379D48DF9AF730';

  FChaCha12_set1v0_256 := 'BAA28ED593690FD760ADA07C95E3B888' +
    '4B4B64E488CA7A2D9BDC262243AB9251' + '394C5037E255F8BCCDCD31306C508FFB' +
    'C9E0161380F7911FCB137D46D9269250';

  FChaCha12_set1v0_448 := 'B7ECFB6AE0B51915762FE1FD03A14D0C' +
    '9E54DA5DC76EB16EBA5313BC535DE63D' + 'C72D7F9F1874E301E99C8531819F4E37' +
    '75793F6A5D19C717FA5C78A39EB804A6';

  // ChaCha8
  FChaCha8_set1v0_0 := 'BEB1E81E0F747E43EE51922B3E87FB38' +
    'D0163907B4ED49336032AB78B67C2457' + '9FE28F751BD3703E51D876C017FAA435' +
    '89E63593E03355A7D57B2366F30047C5';

  FChaCha8_set1v0_192 := '33B8B7CA8F8E89F0095ACE75A379C651' +
    'FD6BDD55703C90672E44C6BAB6AACDD8' + '7C976A87FD264B906E749429284134C2' +
    '38E3B88CF74A68245B860D119A8BDF43';

  FChaCha8_set1v0_256 := 'F7CA95BF08688BD3BE8A27724210F9DC' +
    '16F32AF974FBFB09E9F757C577A245AB' + 'F35F824B70A4C02CB4A8D7191FA8A5AD' +
    '6A84568743844703D353B7F00A8601F4';

  FChaCha8_set1v0_448 := '7B4117E8BFFD595CD8482270B08920FB' +
    'C9B97794E1809E07BB271BF07C861003' + '4C38DBA6ECA04E5474F399A284CBF6E2' +
    '7F70142E604D0977797DE5B58B6B25E0';

end;

procedure TTestChaCha.TearDown;
begin
  inherited;

end;

procedure TTestChaCha.Mismatch(const name, expected: String; found: TBytes);
begin
  Fail(Format('Mismatch on %s, Expected %s, Found %s.',
    [name, expected, EncodeHex(found)]));
end;

procedure TTestChaCha.DoChaChaTest1(rounds: Int32;
  const parameters: ICipherParameters; const v0, v192, v256, v448: String);
var
  chacha: IChaChaEngine;
  buf: TBytes;
  i: Int32;
begin
  chacha := TChaChaEngine.Create(rounds);
  chacha.Init(true, parameters);
  System.SetLength(buf, 64);
  i := 0;
  while i <> 7 do
  begin
    chacha.ProcessBytes(FZeroes, 0, 64, buf, 0);
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
    buf[i] := chacha.ReturnByte(FZeroes[i]);
    System.Inc(i);
  end;

  if not(AreEqual(buf, DecodeHex(v448))) then
  begin
    Mismatch(Format('v448/%d', [rounds]), v448, buf);
  end;
end;

procedure TTestChaCha.DoChaChaTest2(const parameters: ICipherParameters;
  const v0, v65472, v65536: String);
var
  chacha: IChaChaEngine;
  buf: TBytes;
  i: Int32;
begin
  chacha := TChaChaEngine.Create();
  chacha.Init(true, parameters);
  System.SetLength(buf, 64);
  i := 0;
  while i <> 1025 do
  begin
    chacha.ProcessBytes(FZeroes, 0, 64, buf, 0);
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

procedure TTestChaCha.TestDoChaChaTest1;
begin
  DoChaChaTest1(20, TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex('80000000000000000000000000000000'))
    as IKeyParameter, DecodeHex('0000000000000000')) as IParametersWithIV,
    FSet1v0_0, FSet1v0_192, FSet1v0_256, FSet1v0_448);
  DoChaChaTest1(20, TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex('00400000000000000000000000000000'))
    as IKeyParameter, DecodeHex('0000000000000000')) as IParametersWithIV,
    FSet1v9_0, FSet1v9_192, FSet1v9_256, FSet1v9_448);

  DoChaChaTest1(12, TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex('80000000000000000000000000000000'))
    as IKeyParameter, DecodeHex('0000000000000000')), FChaCha12_set1v0_0,
    FChaCha12_set1v0_192, FChaCha12_set1v0_256, FChaCha12_set1v0_448);
  DoChaChaTest1(8, TParametersWithIV.Create
    (TKeyParameter.Create(DecodeHex('80000000000000000000000000000000'))
    as IKeyParameter, DecodeHex('0000000000000000')) as IParametersWithIV,
    FChaCha8_set1v0_0, FChaCha8_set1v0_192, FChaCha8_set1v0_256,
    FChaCha8_set1v0_448);

end;

procedure TTestChaCha.TestDoChaChaTest2;
begin
  DoChaChaTest2(TParametersWithIV.Create(TKeyParameter.Create
    (DecodeHex
    ('0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D'))
    as IKeyParameter, DecodeHex('0D74DB42A91077DE')) as IParametersWithIV,
    FSet6v0_0, FSet6v0_65472, FSet6v0_65536);
  DoChaChaTest2(TParametersWithIV.Create(TKeyParameter.Create
    (DecodeHex
    ('0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12'))
    as IKeyParameter, DecodeHex('167DE44BB21980E7')) as IParametersWithIV,
    FSet6v1_0, FSet6v1_65472, FSet6v1_65536);
end;

procedure TTestChaCha.TestReInitBug;
var
  key: IKeyParameter;
  parameters: IParametersWithIV;
  chacha: IChaChaEngine;
begin
  key := TKeyParameter.Create(DecodeHex('80000000000000000000000000000000'));
  parameters := TParametersWithIV.Create(key, DecodeHex('0000000000000000'));

  chacha := TChaChaEngine.Create();

  chacha.Init(true, parameters);
  try
    chacha.Init(true, key);
    Fail('ChaCha should throw exception if no IV in Init');

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
  RegisterTest(TTestChaCha);
{$ELSE}
  RegisterTest(TTestChaCha.Suite);
{$ENDIF FPC}

end.
