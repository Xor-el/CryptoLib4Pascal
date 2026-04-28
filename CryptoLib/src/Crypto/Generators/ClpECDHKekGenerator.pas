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
  ClpICmsECAsn1Objects,
  ClpCmsECAsn1Objects,
  ClpKdf2BytesGenerator,
  ClpKdfParameters,
  ClpIKdfParameters,
  ClpCheck,
  ClpPack,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort = 'Output buffer too short';
  SECDHKekNotInitialized = 'ECDH KEK generator not initialized';

type
  /// <summary>
  /// X9.63-based key derivation for ECDH CMS (ECC-CMS-SharedInfo, RFC 5753).
  /// </summary>
  TECDHKekGenerator = class sealed(TInterfacedObject, IECDHKekGenerator,
    IDerivationFunction)

  strict private
  var
    FKdf: IDerivationFunction;
    FParams: IDHKdfParameters;

    function GetDigest(): IDigest;
    procedure InitKdf;

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
  if ADigest = nil then
    raise EArgumentNilCryptoLibException.Create('digest');
  FKdf := TKdf2BytesGenerator.Create(ADigest);
end;

function TECDHKekGenerator.GetDigest: IDigest;
begin
  Result := FKdf.Digest;
end;

procedure TECDHKekGenerator.InitKdf;
var
  LKeyInfo: IAlgorithmIdentifier;
  LSuppPub: IAsn1OctetString;
  LEcc: IEccCmsSharedInfo;
  LKdfParams: IKdfParameters;
  LZ: TCryptoLibByteArray;
begin
  if FParams = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SECDHKekNotInitialized);

  LKeyInfo := TAlgorithmIdentifier.Create(FParams.Algorithm, TDerNull.Instance);
  LSuppPub := TDerOctetString.WithContents(
    TPack.UInt32_To_BE(UInt32(FParams.KeySize)));
  LEcc := TEccCmsSharedInfo.Create(LKeyInfo, LSuppPub);
  LZ := FParams.Z;
  LKdfParams := TKdfParameters.Create(LZ, LEcc.GetDerEncoded());
  FKdf.Init(LKdfParams);
end;

procedure TECDHKekGenerator.Init(const AParameters: IDerivationParameters);
var
  LParams: IDHKdfParameters;
begin
  if AParameters = nil then
    raise EArgumentNilCryptoLibException.Create('AParameters');

  if not Supports(AParameters, IDHKdfParameters, LParams) then
    raise EInvalidCastCryptoLibException.Create('AParameters');

  FParams := LParams;
end;

function TECDHKekGenerator.GenerateBytes(const AOutput: TCryptoLibByteArray;
  AOutOff, ALength: Int32): Int32;
begin
  TCheck.OutputLength(AOutput, AOutOff, ALength, SOutputBufferTooShort);
  InitKdf();
  Result := FKdf.GenerateBytes(AOutput, AOutOff, ALength);
end;

end.
