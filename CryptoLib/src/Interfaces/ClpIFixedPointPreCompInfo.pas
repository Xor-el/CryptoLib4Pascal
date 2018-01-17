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

unit ClpIFixedPointPreCompInfo;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIECInterface,
  ClpIPreCompInfo;

type
  IFixedPointPreCompInfo = interface(IPreCompInfo)
    ['{FD2E7BE8-D353-4229-981A-744A50EE9F7F}']

    function GetWidth: Int32;
    procedure SetWidth(const Value: Int32);
    function GetPreComp: TCryptoLibGenericArray<IECPoint>;
    procedure SetPreComp(const Value: TCryptoLibGenericArray<IECPoint>);
    function GetOffset: IECPoint;
    procedure SetOffset(const Value: IECPoint);

    property Offset: IECPoint read GetOffset write SetOffset;
    property PreComp: TCryptoLibGenericArray<IECPoint> read GetPreComp
      write SetPreComp;
    property Width: Int32 read GetWidth write SetWidth;

  end;

implementation

end.
