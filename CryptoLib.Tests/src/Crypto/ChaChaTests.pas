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
  ClpIStreamCipher,
  ClpICipherParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpCryptoLibTypes,
  StreamCipherTestBase,
  CryptoLibTestBase,
  ChaChaPoly1305Vectors;

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
  TTestChaCha = class(TStreamCipherTestBase)
  strict protected
    function GetEngineFactory: TStreamCipherFactory; override;
    function EngineLabel: String; override;
    function KeySizeInBytes: Int32; override;
    function NonceSizeInBytes: Int32; override;
  private
  var
    FZeroes: TBytes;

    function GetCheckpointHex(const ASet: TChaChaKeystreamSet;
      AByteOffset: Integer): string;
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

function CreateChaChaEngine: IStreamCipher;
begin
  Result := TChaChaEngine.Create() as IStreamCipher;
end;

{ TTestChaCha }

function TTestChaCha.GetEngineFactory: TStreamCipherFactory;
begin
  Result := CreateChaChaEngine;
end;

function TTestChaCha.EngineLabel: String;
begin
  Result := 'ChaCha20';
end;

function TTestChaCha.KeySizeInBytes: Int32;
begin
  Result := 32;
end;

function TTestChaCha.NonceSizeInBytes: Int32;
begin
  Result := 8;
end;

function TTestChaCha.GetCheckpointHex(const ASet: TChaChaKeystreamSet;
  AByteOffset: Integer): string;
var
  LI: Integer;
begin
  for LI := 0 to High(ASet.Checkpoints) do
  begin
    if ASet.Checkpoints[LI].ByteOffset = AByteOffset then
      Exit(ASet.Checkpoints[LI].ExpectedKeystream);
  end;
  Fail(Format('No checkpoint at offset %d for set %s',
    [AByteOffset, ASet.SetId]));
end;

procedure TTestChaCha.SetUp;
begin
  inherited;
  FZeroes := DecodeHex('00000000000000000000000000000000' +
    '00000000000000000000000000000000' + '00000000000000000000000000000000' +
    '00000000000000000000000000000000');
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
const
  SET_IDS: array[0..3] of string = (
    'set1v0', 'set1v9', 'chacha12_set1v0', 'chacha8_set1v0');
var
  LI: Integer;
  LSet: TChaChaKeystreamSet;
begin
  for LI := 0 to High(SET_IDS) do
  begin
    LSet := TChaChaVectors.GetKeystreamSet(SET_IDS[LI]);
    DoChaChaTest1(LSet.Rounds, TParametersWithIV.Create
      (TKeyParameter.Create(DecodeHex(LSet.Key)) as IKeyParameter,
      DecodeHex(LSet.Nonce)) as IParametersWithIV,
      GetCheckpointHex(LSet, 0), GetCheckpointHex(LSet, 192),
      GetCheckpointHex(LSet, 256), GetCheckpointHex(LSet, 448));
  end;
end;

procedure TTestChaCha.TestDoChaChaTest2;
const
  SET_IDS: array[0..1] of string = ('set6v0', 'set6v1');
var
  LI: Integer;
  LSet: TChaChaKeystreamSet;
begin
  for LI := 0 to High(SET_IDS) do
  begin
    LSet := TChaChaVectors.GetKeystreamSet(SET_IDS[LI]);
    DoChaChaTest2(TParametersWithIV.Create(TKeyParameter.Create
      (DecodeHex(LSet.Key)) as IKeyParameter, DecodeHex(LSet.Nonce))
      as IParametersWithIV, GetCheckpointHex(LSet, 0),
      GetCheckpointHex(LSet, 65472), GetCheckpointHex(LSet, 65536));
  end;
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
