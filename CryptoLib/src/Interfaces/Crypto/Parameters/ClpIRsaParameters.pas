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

unit ClpIRsaParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIAsymmetricKeyParameter,
  ClpICipherParameters,
  ClpIKeyGenerationParameters;

type
  IRsaKeyParameters = interface(IAsymmetricKeyParameter)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']

    function GetModulus: TBigInteger;
    function GetExponent: TBigInteger;

    function Equals(const AOther: IRsaKeyParameters): Boolean; overload;

    property Modulus: TBigInteger read GetModulus;
    property Exponent: TBigInteger read GetExponent;

  end;

  IRsaPrivateCrtKeyParameters = interface(IRsaKeyParameters)
    ['{B2C3D4E5-F6A7-8901-BCDE-F12345678901}']

    function GetPublicExponent: TBigInteger;
    function GetP: TBigInteger;
    function GetQ: TBigInteger;
    function GetDP: TBigInteger;
    function GetDQ: TBigInteger;
    function GetQInv: TBigInteger;

    property PublicExponent: TBigInteger read GetPublicExponent;
    property P: TBigInteger read GetP;
    property Q: TBigInteger read GetQ;
    property DP: TBigInteger read GetDP;
    property DQ: TBigInteger read GetDQ;
    property QInv: TBigInteger read GetQInv;

  end;

  IRsaKeyGenerationParameters = interface(IKeyGenerationParameters)
    ['{C3D4E5F6-A7B8-9012-CDEF-123456789012}']

    function GetPublicExponent: TBigInteger;
    function GetCertainty: Int32;

    function Equals(const AOther: IRsaKeyGenerationParameters): Boolean;

    property PublicExponent: TBigInteger read GetPublicExponent;
    property Certainty: Int32 read GetCertainty;

  end;

  /// <summary>
  /// Interface for RSA blinding parameters.
  /// </summary>
  IRsaBlindingParameters = interface(ICipherParameters)
    ['{F2A3B4C5-D6E7-8901-2345-6789ABCDEF01}']

    function GetPublicKey: IRsaKeyParameters;
    function GetBlindingFactor: TBigInteger;

    property PublicKey: IRsaKeyParameters read GetPublicKey;
    property BlindingFactor: TBigInteger read GetBlindingFactor;

  end;

implementation

end.
