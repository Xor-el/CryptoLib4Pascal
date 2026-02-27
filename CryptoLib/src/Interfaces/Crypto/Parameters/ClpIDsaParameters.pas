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

unit ClpIDsaParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpISecureRandom,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  IDsaValidationParameters = interface(IInterface)
    ['{F7C394CB-BDC3-47B5-835F-6216FBBF90F9}']

    function GetCounter: Int32;
    function GetUsageIndex: Int32;
    function GetSeed: TCryptoLibByteArray;

    function Equals(const AOther: IDsaValidationParameters): Boolean;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
    property Counter: Int32 read GetCounter;
    property UsageIndex: Int32 read GetUsageIndex;
    property Seed: TCryptoLibByteArray read GetSeed;
  end;

  IDsaParameters = interface(ICipherParameters)
    ['{6A088962-AF58-4699-83B9-ADDABFC65A7E}']

    function GetG: TBigInteger;
    function GetP: TBigInteger;
    function GetQ: TBigInteger;
    function GetValidationParameters: IDsaValidationParameters;

    function Equals(const AOther: IDsaParameters): Boolean;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
    property P: TBigInteger read GetP;
    property Q: TBigInteger read GetQ;
    property G: TBigInteger read GetG;
    property ValidationParameters: IDsaValidationParameters
      read GetValidationParameters;

  end;

  IDsaKeyParameters = interface(IAsymmetricKeyParameter)
    ['{1E3454DF-DC9F-4EA0-91DA-0768A77387C5}']

    function GetParameters: IDsaParameters;

    function Equals(const AOther: IDsaKeyParameters): Boolean; overload;
    property Parameters: IDsaParameters read GetParameters;

  end;

  IDsaPublicKeyParameters = interface(IDsaKeyParameters)
    ['{B3F14490-AF3D-437C-9E42-B6940B2ECADE}']

    function GetY: TBigInteger;

    function Equals(const AOther: IDsaPublicKeyParameters): Boolean; overload;
    property Y: TBigInteger read GetY;

  end;

  IDsaPrivateKeyParameters = interface(IDsaKeyParameters)
    ['{A956E21D-0A60-4073-8F17-5EA8B4615B68}']

    function GetX: TBigInteger;

    function Equals(const AOther: IDsaPrivateKeyParameters): Boolean; overload;
    property X: TBigInteger read GetX;

  end;

  IDsaKeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{0EBFC33A-31D3-4F20-8836-35250F53EA73}']

    function GetParameters: IDsaParameters;

    property Parameters: IDsaParameters read GetParameters;

  end;

  IDsaParameterGenerationParameters = interface(IInterface)
    ['{52ACCC72-7FF6-4934-81E5-F616BEB0EE04}']

    function GetL: Int32;
    property L: Int32 read GetL;

    function GetN: Int32;
    property N: Int32 read GetN;

    function GetUsageIndex: Int32;
    property UsageIndex: Int32 read GetUsageIndex;

    function GetCertainty: Int32;
    property Certainty: Int32 read GetCertainty;

    function GetRandom: ISecureRandom;
    property Random: ISecureRandom read GetRandom;
  end;

implementation

end.
