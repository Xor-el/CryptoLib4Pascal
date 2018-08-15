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

unit ClpTTBCPadding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpITBCPadding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type

  /// <summary> A padder that adds Trailing-Bit-Compliment padding to a block.
  /// <p>
  /// This padding pads the block out compliment of the last bit
  /// of the plain text.
  /// </p>
  /// </summary>
  TTBCPadding = class sealed(TInterfacedObject, ITBCPadding,
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

    /// <summary> add the pad bytes to the passed in block, returning the
    /// number of bytes added.
    /// <p>
    /// Note: this assumes that the last block of plain text is always
    /// passed to it inside in. i.e. if inOff is zero, indicating the
    /// entire block is to be overwritten with padding the value of in
    /// should be the same as the last block of plain text.
    /// </p>
    /// </summary>
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

{ TTBCPadding }

function TTBCPadding.AddPadding(const input: TCryptoLibByteArray;
  inOff: Int32): Int32;
var
  count: Int32;
  code: Byte;
begin
  count := System.Length(input) - inOff;

  if (inOff > 0) then
  begin
    if (input[inOff - 1] and $01) = 0 then
    begin
      code := Byte($FF)
    end
    else
    begin
      code := Byte($00)
    end;

  end
  else
  begin

    if (input[System.Length(input) - 1] and $01) = 0 then
    begin
      code := Byte($FF)
    end
    else
    begin
      code := Byte($00)
    end;

  end;

  while (inOff < System.Length(input)) do
  begin
    input[inOff] := code;
    System.Inc(inOff);
  end;

  result := count;
end;

function TTBCPadding.GetPaddingName: String;
begin
  result := 'TBC';
end;

{$IFNDEF _FIXINSIGHT_}

procedure TTBCPadding.Init(const random: ISecureRandom);
begin
  // nothing to do.
end;
{$ENDIF}

function TTBCPadding.PadCount(const input: TCryptoLibByteArray): Int32;
var
  code: Byte;
  index: Int32;
begin

  code := input[System.Length(input) - 1];

  index := System.Length(input) - 1;
  while ((index > 0) and (input[index - 1] = code)) do
  begin
    System.Dec(index);
  end;

  result := System.Length(input) - index;

end;

end.
