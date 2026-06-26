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

unit DrbgTestSupport;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIEntropySource,
  ClpIEntropySourceProvider,
  ClpArrayUtilities,
  ClpEncoders,
  DrbgTestVectors,
  CryptoLibTestBase;

type
  /// <summary>
  /// Deterministic entropy provider and helpers shared by DRBG vector tests.
  /// </summary>
  TTestEntropySourceProvider = class sealed(TInterfacedObject, IEntropySourceProvider)
  strict private
  type
    TTestEntropySource = class sealed(TInterfacedObject, IEntropySource)
    strict private
      FBitsRequired: Int32;
      FData: TCryptoLibByteArray;
      FIsPredictionResistant: Boolean;
      FIndex: Int32;
    public
      constructor Create(ABitsRequired: Int32; const AData: TCryptoLibByteArray;
        AIsPredictionResistant: Boolean);
      function GetIsPredictionResistant: Boolean;
      function GetEntropy: TCryptoLibByteArray;
      function GetEntropySize: Int32;
    end;

  var
    FData: TCryptoLibByteArray;
    FIsPredictionResistant: Boolean;

  public
    constructor Create(const AData: TCryptoLibByteArray;
      AIsPredictionResistant: Boolean);
    function Get(ABitsRequired: Int32): IEntropySource;
  end;

  /// <summary>
  /// Factory and assertion helpers for DRBG KAT execution.
  /// </summary>
  TDrbgTestSupport = class sealed(TObject)
  public
    class function CreateEntropyProvider(const AProviderName: string)
      : IEntropySourceProvider; static;
    class procedure AssertDrbgOutput(const ATestCase: TCryptoLibAlgorithmTestCase;
      const AExpected, AActual: TCryptoLibByteArray; const AMessage: string); static;
  end;

implementation

{ TTestEntropySourceProvider.TTestEntropySource }

constructor TTestEntropySourceProvider.TTestEntropySource.Create(ABitsRequired: Int32;
  const AData: TCryptoLibByteArray; AIsPredictionResistant: Boolean);
begin
  inherited Create;
  FBitsRequired := ABitsRequired;
  FData := AData;
  FIsPredictionResistant := AIsPredictionResistant;
  FIndex := 0;
end;

function TTestEntropySourceProvider.TTestEntropySource.GetEntropy
  : TCryptoLibByteArray;
var
  LLen: Int32;
begin
  LLen := FBitsRequired div 8;
  System.SetLength(Result, LLen);
  System.Move(FData[FIndex], Result[0], LLen * System.SizeOf(Byte));
  Inc(FIndex, LLen);
end;

function TTestEntropySourceProvider.TTestEntropySource.GetEntropySize: Int32;
begin
  Result := FBitsRequired;
end;

function TTestEntropySourceProvider.TTestEntropySource.GetIsPredictionResistant
  : Boolean;
begin
  Result := FIsPredictionResistant;
end;

{ TTestEntropySourceProvider }

constructor TTestEntropySourceProvider.Create(const AData: TCryptoLibByteArray;
  AIsPredictionResistant: Boolean);
begin
  inherited Create;
  FData := AData;
  FIsPredictionResistant := AIsPredictionResistant;
end;

function TTestEntropySourceProvider.Get(ABitsRequired: Int32): IEntropySource;
begin
  Result := TTestEntropySource.Create(ABitsRequired, FData, FIsPredictionResistant);
end;

{ TDrbgTestSupport }

class function TDrbgTestSupport.CreateEntropyProvider(const AProviderName: string)
  : IEntropySourceProvider;
var
  LInfo: TDrbgEntropyProviderInfo;
begin
  LInfo := TDrbgTestVectors.GetEntropyProvider(AProviderName);
  Result := TTestEntropySourceProvider.Create(LInfo.Data, LInfo.PredictionResistant);
end;

class procedure TDrbgTestSupport.AssertDrbgOutput(
  const ATestCase: TCryptoLibAlgorithmTestCase;
  const AExpected, AActual: TCryptoLibByteArray; const AMessage: string);
begin
  if not TArrayUtilities.AreEqual(AExpected, AActual) then
    ATestCase.Fail(Format('%s expected %s got %s', [AMessage,
      THexEncoder.Encode(AExpected), THexEncoder.Encode(AActual)]));
end;

end.
