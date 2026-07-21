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

unit CtrDrbgTests;

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
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpEncoders,
  ClpAesUtilities,
  ClpIEntropySource,
  ClpIEntropySourceProvider,
  ClpCtrSP800Drbg,
  ClpISP80090Drbg,
  DrbgTestVectors,
  DrbgTestSupport,
  CryptoLibTestBase;

type
  /// <summary>
  /// NIST SP 800-90A AES CTR_DRBG known-answer tests using JSON vectors under
  /// <c>CryptoLib.Tests/Data/Crypto/Drbg/</c>.
  /// </summary>
  TTestCtrDrbg = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestCtrDrbgVectors;
    procedure TestCtrDrbgExceptions;
  end;

implementation

const
  BIT232_ENTROPY_HEX =
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C' +
    '808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C' +
    'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDC';

procedure TTestCtrDrbg.TestCtrDrbgVectors;
var
  LRows: TCryptoLibGenericArray<TDrbgCtrVectorRow>;
  LI: Int32;
  LRow: TDrbgCtrVectorRow;
  LProvider: IEntropySourceProvider;
  LEntropySource: IEntropySource;
  LDrbg: ISP80090Drbg;
  LOutput: TCryptoLibByteArray;
begin
  LRows := TDrbgTestVectors.GetCtrRows;
  for LI := 0 to System.Length(LRows) - 1 do
  begin
    LRow := LRows[LI];
    LProvider := TDrbgTestSupport.CreateEntropyProvider(LRow.EntropyProvider);
    LEntropySource := LProvider.Get(LRow.EntropyBits);
    LDrbg := TCtrSP800Drbg.Create(TAesUtilities.CreateEngine(), LRow.KeySizeBits,
      LRow.SecurityStrength, LEntropySource, LRow.Personalization, LRow.Nonce);

    System.SetLength(LOutput, System.Length(LRow.Expected[0]));
    LDrbg.Generate(LOutput, 0, System.Length(LOutput), LRow.AdditionalInputs[0],
      LRow.PredictionResistant);
    TDrbgTestSupport.AssertDrbgOutput(Self, LRow.Expected[0], LOutput,
      Format('Test #%d.1 failed', [LI + 1]));

    LDrbg.Generate(LOutput, 0, System.Length(LOutput), LRow.AdditionalInputs[1],
      LRow.PredictionResistant);
    TDrbgTestSupport.AssertDrbgOutput(Self, LRow.Expected[1], LOutput,
      Format('Test #%d.2 failed', [LI + 1]));
  end;
end;

procedure TTestCtrDrbg.TestCtrDrbgExceptions;
var
  LBit232Provider: IEntropySourceProvider;
  LDrbg: ISP80090Drbg;
begin
  LBit232Provider := TTestEntropySourceProvider.Create(
    THexEncoder.Decode(BIT232_ENTROPY_HEX), True);

  try
    LDrbg := TCtrSP800Drbg.Create(TAesUtilities.CreateEngine(), 256, 256,
      LBit232Provider.Get(128), nil, nil);
    Fail('no exception thrown');
  except
    on E: EArgumentCryptoLibException do
      CheckEquals('Not enough entropy for security strength required', E.Message);
  end;

  try
    LDrbg := TCtrSP800Drbg.Create(TAesUtilities.CreateEngine(), 192, 256,
      LBit232Provider.Get(232), nil, nil);
    Fail('no exception thrown');
  except
    on E: EArgumentCryptoLibException do
      CheckEquals(
        'Requested security strength is not supported by block cipher and key size',
        E.Message);
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TTestCtrDrbg);
{$ELSE}
RegisterTest(TTestCtrDrbg.Suite);
{$ENDIF FPC}

end.
