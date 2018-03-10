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

unit ClpIX9FieldElement;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECFieldElement,
  ClpIProxiedInterface;

type
  IX9FieldElement = interface(IAsn1Encodable)
    ['{7B055B2C-04BB-438B-B590-9A157F6412C0}']

    function GetValue: IECFieldElement;

    property Value: IECFieldElement read GetValue;

  end;

implementation

end.
