{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIPolynomial;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type

  IPolynomial = interface(IInterface)
    ['{955B9231-3DE9-42D9-9D3C-20B080C1D951}']

    function GetExponentsPresent(): TCryptoLibInt32Array;
    function GetDegree: Int32;
    property Degree: Int32 read GetDegree;

  end;

implementation

end.
