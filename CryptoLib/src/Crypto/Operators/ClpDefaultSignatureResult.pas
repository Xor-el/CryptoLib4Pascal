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

unit ClpDefaultSignatureResult;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockResult,
  ClpISigner,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Interface for default signature result operations.
  /// </summary>
  IDefaultSignatureResult = interface(IBlockResult)
    ['{A3964592-CB32-43F7-9857-D3BFD15FCF80}']
  end;

  /// <summary>
  /// Default implementation of IBlockResult for signature operations.
  /// </summary>
  TDefaultSignatureResult = class sealed(TInterfacedObject, IBlockResult, IDefaultSignatureResult)

  strict private
  var
    FSigner: ISigner;

  public
    constructor Create(const ASigner: ISigner);

    function Collect: TCryptoLibByteArray; overload;
    function Collect(const ABuf: TCryptoLibByteArray; AOff: Int32): Int32; overload;
    function GetMaxResultLength: Int32;
  end;

implementation

{ TDefaultSignatureResult }

constructor TDefaultSignatureResult.Create(const ASigner: ISigner);
begin
  inherited Create();
  FSigner := ASigner;
end;

function TDefaultSignatureResult.Collect: TCryptoLibByteArray;
begin
  Result := FSigner.GenerateSignature();
end;

function TDefaultSignatureResult.Collect(const ABuf: TCryptoLibByteArray; AOff: Int32): Int32;
var
  LSignature: TCryptoLibByteArray;
begin
  LSignature := Collect();
  System.Move(LSignature[0], ABuf[AOff], System.Length(LSignature));
  Result := System.Length(LSignature);
end;

function TDefaultSignatureResult.GetMaxResultLength: Int32;
begin
  Result := FSigner.GetMaxSignatureSize();
end;

end.
