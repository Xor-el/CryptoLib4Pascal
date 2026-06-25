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

unit ClpBasicEntropySourceProvider;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIEntropySource,
  ClpIEntropySourceProvider,
  ClpISecureRandom,
  ClpSecureRandom;

resourcestring
  SSecureRandomNil = 'secureRandom cannot be nil';

type
  TBasicEntropySourceProvider = class sealed(TInterfacedObject, IEntropySourceProvider)
  strict private
  type
    TBasicEntropySource = class sealed(TInterfacedObject, IEntropySource)
    strict private
      FSecureRandom: ISecureRandom;
      FIsPredictionResistant: Boolean;
      FEntropySize: Int32;
    strict protected
      function GetIsPredictionResistant: Boolean;
      function GetEntropy: TCryptoLibByteArray;
      function GetEntropySize: Int32;
    public
      constructor Create(const ASecureRandom: ISecureRandom;
        APredictionResistant: Boolean; AEntropySize: Int32);
    end;

  var
    FSecureRandom: ISecureRandom;
    FIsPredictionResistant: Boolean;

  public
    constructor Create(const ASecureRandom: ISecureRandom;
      AIsPredictionResistant: Boolean);
    function Get(ABitsRequired: Int32): IEntropySource;
  end;

implementation

{ TBasicEntropySourceProvider.TBasicEntropySource }

constructor TBasicEntropySourceProvider.TBasicEntropySource.Create(
  const ASecureRandom: ISecureRandom; APredictionResistant: Boolean;
  AEntropySize: Int32);
begin
  inherited Create;
  if ASecureRandom = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSecureRandomNil);
  FSecureRandom := ASecureRandom;
  FIsPredictionResistant := APredictionResistant;
  FEntropySize := AEntropySize;
end;

function TBasicEntropySourceProvider.TBasicEntropySource.GetEntropy
  : TCryptoLibByteArray;
begin
  Result := TSecureRandom.GetNextBytes(FSecureRandom, (FEntropySize + 7) div 8);
end;

function TBasicEntropySourceProvider.TBasicEntropySource.GetEntropySize: Int32;
begin
  Result := FEntropySize;
end;

function TBasicEntropySourceProvider.TBasicEntropySource.GetIsPredictionResistant
  : Boolean;
begin
  Result := FIsPredictionResistant;
end;

{ TBasicEntropySourceProvider }

constructor TBasicEntropySourceProvider.Create(const ASecureRandom: ISecureRandom;
  AIsPredictionResistant: Boolean);
begin
  inherited Create;
  if ASecureRandom = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSecureRandomNil);
  FSecureRandom := ASecureRandom;
  FIsPredictionResistant := AIsPredictionResistant;
end;

function TBasicEntropySourceProvider.Get(ABitsRequired: Int32): IEntropySource;
begin
  Result := TBasicEntropySource.Create(FSecureRandom, FIsPredictionResistant,
    ABitsRequired);
end;

end.
