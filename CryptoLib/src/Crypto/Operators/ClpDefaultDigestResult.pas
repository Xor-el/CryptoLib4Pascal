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

unit ClpDefaultDigestResult;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockResult,
  ClpIDigest,
  ClpDigestUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Default implementation of IBlockResult for digest operations.
  /// </summary>
  TDefaultDigestResult = class sealed(TInterfacedObject, IBlockResult)

  strict private
  var
    FDigest: IDigest;

  public
    constructor Create(const ADigest: IDigest);

    function Collect: TCryptoLibByteArray; overload;
    function Collect(const ABuf: TCryptoLibByteArray; AOff: Int32): Int32; overload;
    function GetMaxResultLength: Int32;
  end;

implementation

{ TDefaultDigestResult }

constructor TDefaultDigestResult.Create(const ADigest: IDigest);
begin
  inherited Create();
  FDigest := ADigest;
end;

function TDefaultDigestResult.Collect: TCryptoLibByteArray;
begin
  Result := TDigestUtilities.DoFinal(FDigest);
end;

function TDefaultDigestResult.Collect(const ABuf: TCryptoLibByteArray; AOff: Int32): Int32;
begin
  Result := FDigest.DoFinal(ABuf, AOff);
end;

function TDefaultDigestResult.GetMaxResultLength: Int32;
begin
  Result := FDigest.GetDigestSize();
end;

end.
