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

unit ClpIECPublicKeyParameters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECInterface,
  ClpIECKeyParameters;

type

  IECPublicKeyParameters = interface(IECKeyParameters)
    ['{4BABC163-847A-4FE2-AA16-5CD100F76124}']

    function GetQ: IECPoint;

    property Q: IECPoint read GetQ;
  end;

implementation

end.
