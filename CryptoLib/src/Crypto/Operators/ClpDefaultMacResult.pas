{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpDefaultMacResult;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockResult,
  ClpIMac,
  ClpMacUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Default implementation of IBlockResult for MAC operations.
  /// </summary>
  TDefaultMacResult = class sealed(TInterfacedObject, IBlockResult)

  strict private
  var
    FMac: IMac;

  public
    constructor Create(const AMac: IMac);

    function Collect: TCryptoLibByteArray; overload;
    function Collect(const ABuf: TCryptoLibByteArray; AOff: Int32): Int32; overload;
    function GetMaxResultLength: Int32;
  end;

implementation

{ TDefaultMacResult }

constructor TDefaultMacResult.Create(const AMac: IMac);
begin
  inherited Create();
  FMac := AMac;
end;

function TDefaultMacResult.Collect: TCryptoLibByteArray;
begin
  Result := TMacUtilities.DoFinal(FMac);
end;

function TDefaultMacResult.Collect(const ABuf: TCryptoLibByteArray; AOff: Int32): Int32;
begin
  Result := FMac.DoFinal(ABuf, AOff);
end;

function TDefaultMacResult.GetMaxResultLength: Int32;
begin
  Result := FMac.GetMacSize();
end;

end.
