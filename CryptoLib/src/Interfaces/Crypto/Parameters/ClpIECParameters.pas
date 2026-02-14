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

unit ClpIECParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECCommon,
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpIAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpCryptoLibTypes;

type
  IECDomainParameters = interface(IInterface)

    ['{FFF479CD-D7FD-455D-B70C-00D37F8E22A8}']

    function GetCurve: IECCurve;
    function GetG: IECPoint;
    function GetN: TBigInteger;
    function GetH: TBigInteger;

    function GetHInv: TBigInteger;
    function GetSeed: TCryptoLibByteArray;

    property Curve: IECCurve read GetCurve;
    property G: IECPoint read GetG;
    property N: TBigInteger read GetN;
    property H: TBigInteger read GetH;
    property HInv: TBigInteger read GetHInv;
    property Seed: TCryptoLibByteArray read GetSeed;
    function Equals(const AOther: IECDomainParameters): Boolean;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
    function ValidatePrivateScalar(const d: TBigInteger): TBigInteger;
    function ValidatePublicPoint(const q: IECPoint): IECPoint;
    function ToX962Parameters: IX962Parameters;
    function ToX9ECParameters: IX9ECParameters;
  end;

  IECNamedDomainParameters = interface(IECDomainParameters)
    ['{31F8B2D3-B992-41B1-AD08-7CFAD97CD8D1}']

    function GetName: IDerObjectIdentifier;

    property Name: IDerObjectIdentifier read GetName;
  end;

  IECKeyParameters = interface(IAsymmetricKeyParameter)
    ['{50966A0E-21A4-41C3-9246-87B4ED67CE4D}']

    function GetAlgorithmName: String;
    function GetParameters: IECDomainParameters;

    function Equals(const AOther: IECKeyParameters): Boolean; overload;

    property AlgorithmName: String read GetAlgorithmName;
    property Parameters: IECDomainParameters read GetParameters;

  end;

  IECPublicKeyParameters = interface(IECKeyParameters)
    ['{4BABC163-847A-4FE2-AA16-5CD100F76124}']

    function Equals(const AOther: IECPublicKeyParameters): Boolean; overload;
    function GetQ: IECPoint;
    property Q: IECPoint read GetQ;
  end;

  IECPrivateKeyParameters = interface(IECKeyParameters)
    ['{49066428-4021-4E3C-A9F5-AB2127289A67}']

    function Equals(const AOther: IECPrivateKeyParameters): Boolean; overload;
    function GetD: TBigInteger;
    property D: TBigInteger read GetD;
  end;

  IECKeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{B9343CA3-9274-4812-9FFC-2CC27486261E}']

    function GetDomainParameters: IECDomainParameters;
    property DomainParameters: IECDomainParameters read GetDomainParameters;
  end;

implementation

end.
