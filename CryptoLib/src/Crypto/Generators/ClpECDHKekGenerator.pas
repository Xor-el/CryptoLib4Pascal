{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpECDHKekGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIDigest,
  ClpIDerivationFunction,
  ClpIDerivationParameters,
  ClpIECDHKekGenerator,
  ClpIDHKdfParameters,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpKdf2BytesGenerator,
  ClpKdfParameters,
  ClpIKdfParameters,
  ClpPack,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort = 'Output buffer too short';

type
  TECDHKekGenerator = class sealed(TInterfacedObject, IECDHKekGenerator,
    IDerivationFunction)

  strict private
  var
    FKdf: IDerivationFunction;
    FAlgorithm: IDerObjectIdentifier;
    FKeySize: Int32;
    FZ: TCryptoLibByteArray;

    function GetDigest(): IDigest;

  public
    constructor Create(const ADigest: IDigest);

    procedure Init(const AParameters: IDerivationParameters);

    function GenerateBytes(const AOutput: TCryptoLibByteArray;
      AOutOff, ALength: Int32): Int32;

    property Digest: IDigest read GetDigest;
  end;

implementation

{ TECDHKekGenerator }

constructor TECDHKekGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FKdf := TKdf2BytesGenerator.Create(ADigest);
end;

function TECDHKekGenerator.GetDigest: IDigest;
begin
  Result := FKdf.Digest;
end;

procedure TECDHKekGenerator.Init(const AParameters: IDerivationParameters);
var
  LParams: IDHKdfParameters;
begin
  if not Supports(AParameters, IDHKdfParameters, LParams) then
    raise EInvalidCastCryptoLibException.Create('AParameters');

  FAlgorithm := LParams.Algorithm;
  FKeySize := LParams.KeySize;
  FZ := LParams.GetZ();
end;

function TECDHKekGenerator.GenerateBytes(const AOutput: TCryptoLibByteArray;
  AOutOff, ALength: Int32): Int32;
var
  LS: IDerSequence;
  LKdfParams: IKdfParameters;
begin
  if (AOutOff + ALength) > System.Length(AOutput) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  LS := TDerSequence.Create(
    TAlgorithmIdentifier.Create(FAlgorithm, TDerNull.Instance) as IAlgorithmIdentifier,
    TDerTaggedObject.Create(True, 2,
      TDerOctetString.Create(
        TPack.UInt32_To_BE(UInt32(FKeySize))) as IDerOctetString) as IDerTaggedObject);

  LKdfParams := TKdfParameters.Create(FZ, LS.GetDerEncoded());
  FKdf.Init(LKdfParams);

  Result := FKdf.GenerateBytes(AOutput, AOutOff, ALength);
end;

end.
