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

unit ClpISecP384R1Curve;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECInterface,
  ClpBigInteger;

type
  ISecP384R1LookupTable = Interface(IECLookupTable)
    ['{F1354F0B-577F-402C-A363-7761CF82DA43}']
  end;

type
  ISecP384R1Curve = Interface(IAbstractFpCurve)
    ['{50639F3D-E15C-4C3C-A7AA-7A8ACA243341}']

    function GetQ: TBigInteger;
    property Q: TBigInteger read GetQ;

  end;

implementation

end.
