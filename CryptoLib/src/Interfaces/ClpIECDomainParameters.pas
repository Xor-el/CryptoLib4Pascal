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

unit ClpIECDomainParameters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECInterface,
  ClpCryptoLibTypes;

type
  IECDomainParameters = interface(IInterface)

    ['{FFF479CD-D7FD-455D-B70C-00D37F8E22A8}']

    function GetCurve: IECCurve;
    function GetG: IECPoint;
    function GetH: TBigInteger;
    function GetN: TBigInteger;
    function GetSeed: TCryptoLibByteArray;

    property Curve: IECCurve read GetCurve;
    property G: IECPoint read GetG;
    property N: TBigInteger read GetN;
    property H: TBigInteger read GetH;
    property Seed: TCryptoLibByteArray read GetSeed;
    function Equals(other: IECDomainParameters): Boolean;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
  end;

implementation

end.
