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

unit ClpBasicAgreementWithKdf;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpAsn1Objects,
  ClpIDerivationFunction,
  ClpIDHKdfParameters,
  ClpDHKdfParameters,
  ClpGeneratorUtilities,
  ClpBigIntegerUtilities,
  ClpCryptoLibTypes;

type
  TBasicAgreementWithKdf = class sealed(TObject)
  public
    class function CalculateAgreementWithKdf(const AAlgorithm: String;
      const AKdf: IDerivationFunction; AFieldSize: Int32;
      const AResult: TBigInteger): TBigInteger; static;
  end;

implementation

{ TBasicAgreementWithKdf }

class function TBasicAgreementWithKdf.CalculateAgreementWithKdf(
  const AAlgorithm: String; const AKdf: IDerivationFunction;
  AFieldSize: Int32; const AResult: TBigInteger): TBigInteger;
var
  LKeySize: Int32;
  LDhKdfParams: IDHKdfParameters;
  LKeyBytes: TCryptoLibByteArray;
begin
  LKeySize := TGeneratorUtilities.GetDefaultKeySize(AAlgorithm);

  LDhKdfParams := TDHKdfParameters.Create(
    TDerObjectIdentifier.Create(AAlgorithm),
    LKeySize,
    TBigIntegerUtilities.AsUnsignedByteArray(AFieldSize, AResult));

  AKdf.Init(LDhKdfParams);

  System.SetLength(LKeyBytes, LKeySize div 8);
  AKdf.GenerateBytes(LKeyBytes, 0, System.Length(LKeyBytes));

  Result := TBigInteger.Create(1, LKeyBytes);
end;

end.
