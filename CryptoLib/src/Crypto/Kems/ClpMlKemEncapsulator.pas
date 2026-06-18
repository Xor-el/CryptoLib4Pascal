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

unit ClpMlKemEncapsulator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIKemEncapsulator,
  ClpIMlKemParameters,
  ClpIMlKemEngine,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpCryptoServicesRegistrar,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpArrayUtilities,
  ClpMlKemEngine,
  ClpMlKemCore,
  ClpCryptoLibTypes;

resourcestring
  SMlKemEncapsulatorExpectsPublicKey = 'TMlKemEncapsulator expects IMlKemPublicKeyParameters';
  SMismatchingKeyParameterSet = 'mismatching key parameter set';

type
  TMlKemEncapsulator = class(TInterfacedObject, IKemEncapsulator)
  strict private
  var
    FParameters: IMlKemParameters;
    FPublicKey: IMlKemPublicKeyParameters;
    FRandom: ISecureRandom;
    FEngine: IMlKemEngine;
    function GetEngine(const AKeyParameters: IMlKemParameters): IMlKemEngine;
  public
    constructor Create(const AParameters: IMlKemParameters);
    procedure Init(const AParameters: ICipherParameters);
    function GetEncapsulationLength: Int32;
    function GetSecretLength: Int32;
    procedure Encapsulate(const AEncBuf: TCryptoLibByteArray; AEncOff, AEncLen: Int32;
      const ASecBuf: TCryptoLibByteArray; ASecOff, ASecLen: Int32);

    property EncapsulationLength: Int32 read GetEncapsulationLength;
    property SecretLength: Int32 read GetSecretLength;
  end;

implementation

{ TMlKemEncapsulator }

constructor TMlKemEncapsulator.Create(const AParameters: IMlKemParameters);
begin
  inherited Create;
  FParameters := AParameters;
end;

procedure TMlKemEncapsulator.Encapsulate(const AEncBuf: TCryptoLibByteArray;
  AEncOff, AEncLen: Int32; const ASecBuf: TCryptoLibByteArray; ASecOff, ASecLen: Int32);
var
  LRandBytes: TCryptoLibByteArray;
begin
  TArrayUtilities.ValidateSegment(AEncBuf, AEncOff, AEncLen);
  TArrayUtilities.ValidateSegment(ASecBuf, ASecOff, ASecLen);
  if EncapsulationLength <> AEncLen then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  if SecretLength <> ASecLen then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  LRandBytes := TSecureRandom.GetNextBytes(FRandom, MlKemSymBytes);
  FEngine.KemEncrypt(FPublicKey.Encoding, LRandBytes, AEncBuf, AEncOff, ASecBuf, ASecOff);
end;

function TMlKemEncapsulator.GetEngine(const AKeyParameters: IMlKemParameters): IMlKemEngine;
begin
  if AKeyParameters.ParameterSet <> FParameters.ParameterSet then
    raise EArgumentCryptoLibException.CreateRes(@SMismatchingKeyParameterSet);
  Result := AKeyParameters.ParameterSet.Engine;
end;

function TMlKemEncapsulator.GetEncapsulationLength: Int32;
begin
  Result := FEngine.CipherTextBytes;
end;

function TMlKemEncapsulator.GetSecretLength: Int32;
begin
  Result := TMlKemEngine.SharedSecretBytes;
end;

procedure TMlKemEncapsulator.Init(const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
  LProvidedRandom: ISecureRandom;
begin
  LParameters := AParameters;
  LParameters := TParameterUtilities.GetRandom(LParameters, LProvidedRandom);
  if not Supports(LParameters, IMlKemPublicKeyParameters, FPublicKey) then
    raise EArgumentCryptoLibException.CreateRes(@SMlKemEncapsulatorExpectsPublicKey);
  FRandom := TCryptoServicesRegistrar.GetSecureRandom(LProvidedRandom);
  FEngine := GetEngine(FPublicKey.Parameters);
end;

end.
