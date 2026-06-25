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

unit ClpCryptoApiEntropySourceProvider;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIEntropySource,
  ClpIEntropySourceProvider,
  ClpIRandomNumberGenerator,
  ClpRandomNumberGenerator;

resourcestring
  SRngNil = 'rng cannot be nil';

type
  TCryptoApiEntropySourceProvider = class sealed(TInterfacedObject,
    IEntropySourceProvider)
  strict private
  type
    TCryptoApiEntropySource = class sealed(TInterfacedObject, IEntropySource)
    strict private
      FRng: IRandomNumberGenerator;
      FIsPredictionResistant: Boolean;
      FEntropySize: Int32;
    strict protected
      function GetIsPredictionResistant: Boolean;
      function GetEntropy: TCryptoLibByteArray;
      function GetEntropySize: Int32;
    public
      constructor Create(const ARng: IRandomNumberGenerator;
        APredictionResistant: Boolean; AEntropySize: Int32);
    end;

  var
    FRng: IRandomNumberGenerator;
    FIsPredictionResistant: Boolean;

  public
    constructor Create(); overload;
    constructor Create(const ARng: IRandomNumberGenerator;
      AIsPredictionResistant: Boolean); overload;
    function Get(ABitsRequired: Int32): IEntropySource;
  end;

implementation

{ TCryptoApiEntropySourceProvider.TCryptoApiEntropySource }

constructor TCryptoApiEntropySourceProvider.TCryptoApiEntropySource.Create(
  const ARng: IRandomNumberGenerator; APredictionResistant: Boolean;
  AEntropySize: Int32);
begin
  inherited Create;
  if ARng = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SRngNil);
  FRng := ARng;
  FIsPredictionResistant := APredictionResistant;
  FEntropySize := AEntropySize;
end;

function TCryptoApiEntropySourceProvider.TCryptoApiEntropySource.GetEntropy
  : TCryptoLibByteArray;
begin
  System.SetLength(Result, (FEntropySize + 7) div 8);
  FRng.GetBytes(Result);
end;

function TCryptoApiEntropySourceProvider.TCryptoApiEntropySource.GetEntropySize
  : Int32;
begin
  Result := FEntropySize;
end;

function TCryptoApiEntropySourceProvider.TCryptoApiEntropySource.
  GetIsPredictionResistant: Boolean;
begin
  Result := FIsPredictionResistant;
end;

{ TCryptoApiEntropySourceProvider }

constructor TCryptoApiEntropySourceProvider.Create;
begin
  Create(TRandomNumberGenerator.CreateRng(), True);
end;

constructor TCryptoApiEntropySourceProvider.Create(const ARng: IRandomNumberGenerator;
  AIsPredictionResistant: Boolean);
begin
  inherited Create;
  if ARng = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SRngNil);
  FRng := ARng;
  FIsPredictionResistant := AIsPredictionResistant;
end;

function TCryptoApiEntropySourceProvider.Get(ABitsRequired: Int32): IEntropySource;
begin
  Result := TCryptoApiEntropySource.Create(FRng, FIsPredictionResistant,
    ABitsRequired);
end;

end.
