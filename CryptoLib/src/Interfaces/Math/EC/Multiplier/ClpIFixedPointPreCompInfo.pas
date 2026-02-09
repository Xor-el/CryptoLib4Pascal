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

unit ClpIFixedPointPreCompInfo;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCommon,
  ClpIPreCompInfo,
  ClpCryptoLibTypes;

type
  IFixedPointPreCompInfo = interface(IPreCompInfo)
    ['{D2E3F4A5-B6C7-8901-DEF0-234567890ABC}']
    function GetLookupTable: IECLookupTable;
    procedure SetLookupTable(const AValue: IECLookupTable);
    function GetOffset: IECPoint;
    procedure SetOffset(const AValue: IECPoint);
    function GetWidth: Int32;
    procedure SetWidth(AValue: Int32);
    property LookupTable: IECLookupTable read GetLookupTable write SetLookupTable;
    property Offset: IECPoint read GetOffset write SetOffset;
    property Width: Int32 read GetWidth write SetWidth;
  end;

implementation

end.
