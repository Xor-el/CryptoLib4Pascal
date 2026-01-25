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

unit ClpIRsaKeyParameters;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIAsymmetricKeyParameter;

type
  IRsaKeyParameters = interface(IAsymmetricKeyParameter)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']

    function GetModulus: TBigInteger;
    function GetExponent: TBigInteger;

    function Equals(const other: IRsaKeyParameters): Boolean; overload;

    property Modulus: TBigInteger read GetModulus;
    property Exponent: TBigInteger read GetExponent;

  end;

implementation

end.
