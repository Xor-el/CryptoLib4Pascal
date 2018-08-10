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

unit ClpISecT283K1Curve;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECInterface;

type
  ISecT283K1LookupTable = Interface(IECLookupTable)
    ['{3AF41553-A108-46D6-9CCC-AB1814A0A247}']
  end;

type
  ISecT283K1Curve = Interface(IAbstractF2mCurve)
    ['{1D88AF22-721F-4E89-82A2-1C1CFFB7830C}']

    function GetM: Int32;
    property M: Int32 read GetM;

    function GetK1: Int32;
    property K1: Int32 read GetK1;

    function GetK2: Int32;
    property K2: Int32 read GetK2;

    function GetK3: Int32;
    property K3: Int32 read GetK3;

    function GetIsTrinomial: Boolean;
    property IsTrinomial: Boolean read GetIsTrinomial;

  end;

implementation

end.
