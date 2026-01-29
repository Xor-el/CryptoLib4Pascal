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

unit ClpIPkcsRsaAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for RsaPrivateKeyStructure.
  /// </summary>
  IRsaPrivateKeyStructure = interface(IAsn1Encodable)
    ['{F7A8B9C0-D1E2-F345-A6B7-C8D9E0F1A2B3}']

    function GetModulus: TBigInteger;
    function GetPublicExponent: TBigInteger;
    function GetPrivateExponent: TBigInteger;
    function GetPrime1: TBigInteger;
    function GetPrime2: TBigInteger;
    function GetExponent1: TBigInteger;
    function GetExponent2: TBigInteger;
    function GetCoefficient: TBigInteger;

    property Modulus: TBigInteger read GetModulus;
    property PublicExponent: TBigInteger read GetPublicExponent;
    property PrivateExponent: TBigInteger read GetPrivateExponent;
    property Prime1: TBigInteger read GetPrime1;
    property Prime2: TBigInteger read GetPrime2;
    property Exponent1: TBigInteger read GetExponent1;
    property Exponent2: TBigInteger read GetExponent2;
    property Coefficient: TBigInteger read GetCoefficient;
  end;

  /// <summary>
  /// Interface for RsassaPssParameters.
  /// </summary>
  IRsassaPssParameters = interface(IAsn1Encodable)
    ['{A8B9C0D1-E2F3-4567-8901-23456789ABCD}']

    function GetHashAlgorithm: IAlgorithmIdentifier;
    function GetMaskGenAlgorithm: IAlgorithmIdentifier;
    function GetSaltLength: IDerInteger;
    function GetTrailerField: IDerInteger;

    property HashAlgorithm: IAlgorithmIdentifier read GetHashAlgorithm;
    property MaskGenAlgorithm: IAlgorithmIdentifier read GetMaskGenAlgorithm;
    property SaltLength: IDerInteger read GetSaltLength;
    property TrailerField: IDerInteger read GetTrailerField;
  end;

implementation

end.
