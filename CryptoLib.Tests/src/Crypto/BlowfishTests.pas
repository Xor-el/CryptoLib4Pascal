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

unit BlowfishTests;

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
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpBlowfishEngine,
  ClpIBlowfishEngine,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpBufferedBlockCipher,
  ClpIBufferedBlockCipher,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Blowfish tester - vectors from http://www.counterpane.com/vectors.txt
  /// </summary>
  TTestBlowfish = class(TCryptoLibAlgorithmTestCase)
  strict private
  class var

    FBlockCipherVectorKeys, FBlockCipherVectorInputs,
    FBlockCipherVectorOutputs: TCryptoLibStringArray;

    class constructor CreateTestVectors();

  private

    procedure DoBlockCipherVectorTest(const AEngine: IBlockCipher;
      const AParam: ICipherParameters; const AInput, AOutput: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestBlockCipherVector;

  end;

implementation

{ TTestBlowfish }

class constructor TTestBlowfish.CreateTestVectors;
begin
  FBlockCipherVectorKeys := TCryptoLibStringArray.Create
    ('0000000000000000', 'FFFFFFFFFFFFFFFF',
    '3000000000000000',
    '1111111111111111', '0123456789ABCDEF', 'FEDCBA9876543210',
    '7CA110454A1A6E57', '0131D9619DC1376E');

  FBlockCipherVectorInputs := TCryptoLibStringArray.Create
    ('0000000000000000', 'FFFFFFFFFFFFFFFF',
    '1000000000000001',
    '1111111111111111', '1111111111111111', '0123456789ABCDEF',
    '01A1D6D039776742', '5CD54CA83DEF57DA');

  FBlockCipherVectorOutputs := TCryptoLibStringArray.Create
    ('4EF997456198DD78', '51866FD5B85ECB8A',
    '7D856F9A613063F2',
    '2466DD878B963C9D', '61F9C3802281B096', '0ACEAB0FC6A0A28D',
    '59C68245EB05282B', 'B1B8CC0B250F09A0');
end;

procedure TTestBlowfish.DoBlockCipherVectorTest(const AEngine: IBlockCipher;
  const AParam: ICipherParameters; const AInput, AOutput: String);
var
  LCipher: IBufferedBlockCipher;
  LLen1, LLen2: Int32;
  LInput, LOutput, LOutBytes: TBytes;
begin
  LInput := DecodeHex(AInput);
  LOutput := DecodeHex(AOutput);

  LCipher := TBufferedBlockCipher.Create(AEngine);

  LCipher.Init(True, AParam);

  System.SetLength(LOutBytes, System.Length(LInput));

  LLen1 := LCipher.ProcessBytes(LInput, 0, System.Length(LInput), LOutBytes, 0);

  LCipher.DoFinal(LOutBytes, LLen1);

  if (not AreEqual(LOutBytes, LOutput)) then
  begin
    Fail(Format('Encryption Failed - Expected %s but got %s',
      [EncodeHex(LOutput), EncodeHex(LOutBytes)]));
  end;

  LCipher.Init(False, AParam);

  LLen2 := LCipher.ProcessBytes(LOutput, 0, System.Length(LOutput),
    LOutBytes, 0);

  LCipher.DoFinal(LOutBytes, LLen2);

  if (not AreEqual(LInput, LOutBytes)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(LInput), EncodeHex(LOutBytes)]));
  end;
end;

procedure TTestBlowfish.SetUp;
begin
  inherited;
end;

procedure TTestBlowfish.TearDown;
begin
  inherited;
end;

procedure TTestBlowfish.TestBlockCipherVector;
var
  LI: Int32;
begin
  for LI := System.Low(FBlockCipherVectorKeys)
    to System.High(FBlockCipherVectorKeys) do
  begin
    DoBlockCipherVectorTest(TBlowfishEngine.Create() as IBlowfishEngine,
      TKeyParameter.Create(DecodeHex(FBlockCipherVectorKeys[LI]))
      as IKeyParameter, FBlockCipherVectorInputs[LI],
      FBlockCipherVectorOutputs[LI]);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestBlowfish);
{$ELSE}
  RegisterTest(TTestBlowfish.Suite);
{$ENDIF FPC}

end.
