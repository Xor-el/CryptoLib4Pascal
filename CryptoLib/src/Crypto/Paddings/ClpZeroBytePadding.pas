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

unit ClpZeroBytePadding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIZeroBytePadding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// A padder that adds Null byte padding to a block.
  /// </summary>
  TZeroBytePadding = class sealed(TInterfacedObject, IZeroBytePadding,
    IBlockCipherPadding)

  strict private

    /// <returns>
    /// return the name of the algorithm the cipher implements.
    /// </returns>
    function GetPaddingName: String; inline;

  public
    /// <summary>
    /// Initialise the padder.
    /// </summary>
    /// <param name="random">
    /// a SecureRandom if available.
    /// </param>
    procedure Init(const random: ISecureRandom);

    /// <summary>
    /// Return the name of the algorithm the cipher implements.
    /// </summary>
    property PaddingName: String read GetPaddingName;

    /// <summary>
    /// add the pad bytes to the passed in block, returning the number of
    /// bytes added.
    /// </summary>
    /// <param name="input">
    /// input block to pad
    /// </param>
    /// <param name="inOff">
    /// offset to start the padding from in the block
    /// </param>
    /// <returns>
    /// returns number of bytes added
    /// </returns>
    function AddPadding(const input: TCryptoLibByteArray; inOff: Int32): Int32;

    /// <summary>
    /// return the number of pad bytes present in the block.
    /// </summary>
    /// <param name="input">
    /// block to count pad bytes in
    /// </param>
    /// <returns>
    /// the number of pad bytes present in the block.
    /// </returns>
    function PadCount(const input: TCryptoLibByteArray): Int32;

  end;

implementation

{ TZeroBytePadding }

function TZeroBytePadding.AddPadding(const input: TCryptoLibByteArray;
  inOff: Int32): Int32;
var
  added: Int32;
begin
  added := System.Length(input) - inOff;

  while (inOff < System.Length(input)) do
  begin
    input[inOff] := Byte(0);
    System.Inc(inOff);
  end;

  result := added;
end;

function TZeroBytePadding.GetPaddingName: String;
begin
  result := 'ZeroBytePadding';
end;

{$IFNDEF _FIXINSIGHT_}

procedure TZeroBytePadding.Init(const random: ISecureRandom);
begin
  // nothing to do.
end;
{$ENDIF}

function TZeroBytePadding.PadCount(const input: TCryptoLibByteArray): Int32;
var
  count: Int32;
begin
  count := System.Length(input);
  while (count > 0) do
  begin
    if (input[count - 1] <> 0) then
    begin
      break;
    end;

    System.Dec(count);
  end;

  result := System.Length(input) - count;
end;

end.
