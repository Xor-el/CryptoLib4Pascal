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

unit ClpIRsaPrivateCrtKeyParameters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIRsaKeyParameters;

type
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

implementation

end.
