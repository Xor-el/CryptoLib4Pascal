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

unit ClpIX9ECPoint;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpIECInterface;

type

  IX9ECPoint = interface(IAsn1Encodable)
    ['{B91190B8-A56A-4231-9687-24E4BB1397C7}']

    function GetPointEncoding(): TCryptoLibByteArray;
    function GetIsPointCompressed: Boolean;
    function GetPoint: IECPoint;
    property Point: IECPoint read GetPoint;
    property IsPointCompressed: Boolean read GetIsPointCompressed;

  end;

implementation

end.
