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

unit ClpISecP256K1Curve;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECInterface,
  ClpBigInteger;

type
  ISecP256K1LookupTable = Interface(IECLookupTable)
    ['{0E204483-F303-49FD-AF66-0F30CF855CA9}']
  end;

type
  ISecP256K1Curve = Interface(IAbstractFpCurve)
    ['{BBE4D704-8562-4C17-9149-CA33CFE7611F}']

    function GetQ: TBigInteger;
    property Q: TBigInteger read GetQ;

  end;

implementation

end.
