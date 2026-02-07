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

unit ClpIEndoPreCompInfo;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCore,
  ClpIPreCompInfo;

type
  IEndoPreCompInfo = interface(IPreCompInfo)
    ['{B1C2D3E4-F5A6-7890-BCDE-F12345678903}']
    function GetEndomorphism: IECEndomorphism;
    procedure SetEndomorphism(const AValue: IECEndomorphism);
    function GetMappedPoint: IECPoint;
    procedure SetMappedPoint(const AValue: IECPoint);
    property Endomorphism: IECEndomorphism read GetEndomorphism write SetEndomorphism;
    property MappedPoint: IECPoint read GetMappedPoint write SetMappedPoint;
  end;

implementation

end.
