{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpECDHCWithKdfBasicAgreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpICipherParameters,
  ClpIBasicAgreement,
  ClpIECDHCBasicAgreement,
  ClpIECDHCWithKdfBasicAgreement,
  ClpECDHCBasicAgreement,
  ClpIDerivationFunction,
  ClpBasicAgreementWithKdf,
  ClpCryptoLibTypes;

type
  TECDHCWithKdfBasicAgreement = class sealed(TECDHCBasicAgreement,
    IECDHCWithKdfBasicAgreement, IECDHCBasicAgreement, IBasicAgreement)

  strict private
  var
    FAlgorithm: String;
    FKdf: IDerivationFunction;

  public
    constructor Create(const AAlgorithm: String;
      const AKdf: IDerivationFunction);

    function CalculateAgreement(const APubKey: ICipherParameters): TBigInteger; override;
  end;

implementation

{ TECDHCWithKdfBasicAgreement }

constructor TECDHCWithKdfBasicAgreement.Create(const AAlgorithm: String;
  const AKdf: IDerivationFunction);
begin
  inherited Create();
  if AAlgorithm = '' then
    raise EArgumentNilCryptoLibException.Create('AAlgorithm');
  if AKdf = nil then
    raise EArgumentNilCryptoLibException.Create('AKdf');
  FAlgorithm := AAlgorithm;
  FKdf := AKdf;
end;

function TECDHCWithKdfBasicAgreement.CalculateAgreement(
  const APubKey: ICipherParameters): TBigInteger;
var
  LResult: TBigInteger;
begin
  LResult := inherited CalculateAgreement(APubKey);
  Result := TBasicAgreementWithKdf.CalculateAgreementWithKdf(FAlgorithm, FKdf,
    GetFieldSize(), LResult);
end;

end.
