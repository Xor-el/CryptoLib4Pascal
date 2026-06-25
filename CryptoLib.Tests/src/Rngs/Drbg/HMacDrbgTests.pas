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

unit HMacDrbgTests;

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
  ClpMacUtilities,
  ClpIEntropySource,
  ClpIEntropySourceProvider,
  ClpHMacSP800Drbg,
  ClpISP80090Drbg,
  DrbgTestVectors,
  DrbgTestSupport,
  CryptoLibTestBase;

type
  TTestHMacDrbg = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestHMacDrbgVectors;
    procedure TestHMacDrbgExceptions;
  end;

implementation

procedure TTestHMacDrbg.TestHMacDrbgVectors;
var
  LRows: TCryptoLibGenericArray<TDrbgHMacVectorRow>;
  LI: Int32;
  LRow: TDrbgHMacVectorRow;
  LProvider: IEntropySourceProvider;
  LEntropySource: IEntropySource;
  LDrbg: ISP80090Drbg;
  LOutput: TCryptoLibByteArray;
begin
  LRows := TDrbgTestVectors.GetHMacRows;
  for LI := 0 to System.Length(LRows) - 1 do
  begin
    LRow := LRows[LI];
    LProvider := TDrbgTestSupport.CreateEntropyProvider(LRow.EntropyProvider);
    LEntropySource := LProvider.Get(LRow.EntropyBits);
    LDrbg := THMacSP800Drbg.Create(TMacUtilities.GetMac(LRow.Mac),
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

procedure TTestHMacDrbg.TestHMacDrbgExceptions;
var
  LProvider: IEntropySourceProvider;
  LDrbg: ISP80090Drbg;
begin
  LProvider := TDrbgTestSupport.CreateEntropyProvider('SHA256');
  try
    LDrbg := THMacSP800Drbg.Create(TMacUtilities.GetMac('HMAC-SHA-256'), 256,
      LProvider.Get(128), nil, nil);
    Fail('no exception thrown');
  except
    on E: EArgumentCryptoLibException do
      CheckEquals('Not enough entropy for security strength required', E.Message);
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TTestHMacDrbg);
{$ELSE}
RegisterTest(TTestHMacDrbg.Suite);
{$ENDIF FPC}

end.
