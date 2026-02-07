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

unit ClpAbstractECLookupTable;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIECCore;

type
  TAbstractECLookupTable = class abstract(TInterfacedObject, IECLookupTable)
  public
    function Lookup(AIndex: Int32): IECPoint; virtual; abstract;
    function GetSize: Int32; virtual; abstract;
    function LookupVar(AIndex: Int32): IECPoint; virtual;
    property Size: Int32 read GetSize;
  end;

implementation

function TAbstractECLookupTable.LookupVar(AIndex: Int32): IECPoint;
begin
  Result := Lookup(AIndex);
end;

end.
