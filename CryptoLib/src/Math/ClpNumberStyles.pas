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

unit ClpNumberStyles;

{$I ..\Include\CryptoLib.inc}

interface

type
{$SCOPEDENUMS ON}
  TNumberStyles = (None = 0, AllowLeadingWhite = 1, AllowTrailingWhite = 2,
    AllowLeadingSign = 4, Integer = 4 or 2 or 1, AllowTrailingSign = 8,
    AllowParentheses = 16, AllowDecimalPoint = 32, AllowThousands = 64,
    AllowExponent = 128, AllowCurrencySymbol = 256, AllowHexSpecifier = 512);
{$SCOPEDENUMS OFF}

implementation

end.
