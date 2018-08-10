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

unit ClpISecP521R1Curve;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECInterface,
  ClpBigInteger;

type
  ISecP521R1LookupTable = Interface(IECLookupTable)
    ['{3A647191-94A9-483D-9AC5-57FEFDBA3060}']
  end;

type
  ISecP521R1Curve = Interface(IAbstractFpCurve)
    ['{B2AACD7E-6EF2-45E2-8126-FB87D6DB65B1}']

    function GetQ: TBigInteger;
    property Q: TBigInteger read GetQ;

  end;

implementation

end.
