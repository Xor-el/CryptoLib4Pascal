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

unit ClpIDHParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpIAsymmetricKeyParameter,
  ClpIKeyGenerationParameters,
  ClpIAsn1Objects,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  IDHValidationParameters = interface(IInterface)
    ['{6F7404A7-0588-4154-8955-8C1A5C757B17}']

    function GetCounter: Int32;
    function GetSeed: TCryptoLibByteArray;

    function Equals(const AOther: IDHValidationParameters): Boolean;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
    property Counter: Int32 read GetCounter;
    property Seed: TCryptoLibByteArray read GetSeed;
  end;

  IDHParameters = interface(ICipherParameters)
    ['{6609D678-F9FB-48FD-A22F-52AFAE9EA5F8}']

    function GetG: TBigInteger;
    property G: TBigInteger read GetG;

    function GetP: TBigInteger;
    property P: TBigInteger read GetP;

    function GetQ: TBigInteger;
    property Q: TBigInteger read GetQ;

    function GetJ: TBigInteger;
    property J: TBigInteger read GetJ;

    function GetM: Int32;
    property M: Int32 read GetM;

    function GetL: Int32;
    property L: Int32 read GetL;

    function GetValidationParameters: IDHValidationParameters;
    property ValidationParameters: IDHValidationParameters
      read GetValidationParameters;

    function Equals(const AOther: IDHParameters): Boolean;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
  end;

  IDHKeyParameters = interface(IAsymmetricKeyParameter)
    ['{53834D98-B75A-4607-BA38-3CD9DE3B3CF4}']

    function GetParameters: IDHParameters;
    function GetAlgorithmOid: IDerObjectIdentifier;

    function Equals(const AOther: IDHKeyParameters): Boolean; overload;
    property Parameters: IDHParameters read GetParameters;
    property AlgorithmOid: IDerObjectIdentifier read GetAlgorithmOid;

  end;

  IDHPublicKeyParameters = interface(IDHKeyParameters)
    ['{F78EC20B-B591-42AB-87F3-22011F1DE05E}']

    function GetY: TBigInteger;

    function Equals(const AOther: IDHPublicKeyParameters): Boolean; overload;
    property Y: TBigInteger read GetY;

  end;

  IDHPrivateKeyParameters = interface(IDHKeyParameters)
    ['{946AD4C3-6B77-46F5-871C-C8958DD371E0}']

    function GetX: TBigInteger;

    function Equals(const AOther: IDHPrivateKeyParameters): Boolean; overload;
    property X: TBigInteger read GetX;

  end;

  IDHKeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{B513182A-1697-468E-A090-0E09C246BD8B}']

    function GetParameters: IDHParameters;

    property Parameters: IDHParameters read GetParameters;

  end;

implementation

end.
