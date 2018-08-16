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

unit ClpISecP256R1Curve;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECInterface,
  ClpBigInteger;

type
  ISecP256R1LookupTable = Interface(IECLookupTable)
    ['{87BF97BA-18D2-4248-ABEB-8E429998E9D9}']
  end;

type
  ISecP256R1Curve = Interface(IAbstractFpCurve)
    ['{D6B64687-91B2-4281-B099-3B3DCFB330DB}']

    function GetQ: TBigInteger;
    property Q: TBigInteger read GetQ;

  end;

implementation

end.
