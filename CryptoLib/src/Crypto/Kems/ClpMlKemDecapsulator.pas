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

unit ClpMlKemDecapsulator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIKemDecapsulator,
  ClpIMlKemParameters,
  ClpIMlKemEngine,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpArrayUtilities,
  ClpMlKemEngine,
  ClpCryptoLibTypes;

resourcestring
  SMlKemDecapsulationRequiresPrivateKey = 'ML-KEM decapsulation requires private key';
  SMismatchingKeyParameterSet = 'mismatching key parameter set';

type
  TMlKemDecapsulator = class(TInterfacedObject, IKemDecapsulator)
  strict private
  var
    FParameters: IMlKemParameters;
    FPrivateKey: IMlKemPrivateKeyParameters;
    FEngine: IMlKemEngine;
    function GetEngine(const AKeyParameters: IMlKemParameters): IMlKemEngine;
  public
    constructor Create(const AParameters: IMlKemParameters);
    procedure Init(const AParameters: ICipherParameters);
    function GetEncapsulationLength: Int32;
    function GetSecretLength: Int32;
    procedure Decapsulate(const AEncBuf: TCryptoLibByteArray; AEncOff, AEncLen: Int32;
      const ASecBuf: TCryptoLibByteArray; ASecOff, ASecLen: Int32);

    property EncapsulationLength: Int32 read GetEncapsulationLength;
    property SecretLength: Int32 read GetSecretLength;
  end;

implementation

{ TMlKemDecapsulator }

constructor TMlKemDecapsulator.Create(const AParameters: IMlKemParameters);
begin
  inherited Create;
  FParameters := AParameters;
end;

procedure TMlKemDecapsulator.Decapsulate(const AEncBuf: TCryptoLibByteArray;
  AEncOff, AEncLen: Int32; const ASecBuf: TCryptoLibByteArray; ASecOff, ASecLen: Int32);
begin
  TArrayUtilities.ValidateSegment(AEncBuf, AEncOff, AEncLen);
  TArrayUtilities.ValidateSegment(ASecBuf, ASecOff, ASecLen);
  if EncapsulationLength <> AEncLen then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  if SecretLength <> ASecLen then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  FEngine.KemDecrypt(FPrivateKey.Encoding, AEncBuf, AEncOff, ASecBuf, ASecOff);
end;

function TMlKemDecapsulator.GetEngine(const AKeyParameters: IMlKemParameters): IMlKemEngine;
begin
  if AKeyParameters.ParameterSet <> FParameters.ParameterSet then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  Result := AKeyParameters.ParameterSet.Engine;
end;

function TMlKemDecapsulator.GetEncapsulationLength: Int32;
begin
  Result := FEngine.CipherTextBytes;
end;

function TMlKemDecapsulator.GetSecretLength: Int32;
begin
  Result := TMlKemEngine.SharedSecretBytes;
end;

procedure TMlKemDecapsulator.Init(const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
begin
  LParameters := TParameterUtilities.IgnoreRandom(AParameters);
  if not Supports(LParameters, IMlKemPrivateKeyParameters, FPrivateKey) then
    raise EArgumentCryptoLibException.CreateRes(@SMlKemDecapsulationRequiresPrivateKey);
  FEngine := GetEngine(FPrivateKey.Parameters);
end;

end.
