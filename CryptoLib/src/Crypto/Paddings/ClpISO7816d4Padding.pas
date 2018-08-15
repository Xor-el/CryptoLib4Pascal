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

unit ClpISO7816d4Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIISO7816d4Padding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'Pad Block Corrupted';

type

  /// <summary>
  /// A padder that adds the padding according to the scheme referenced in
  /// ISO 7814-4 - scheme 2 from ISO 9797-1. The first byte is $80, rest is $00
  /// </summary>
  TISO7816d4Padding = class sealed(TInterfacedObject, IISO7816d4Padding,
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
    /// <exception cref="EInvalidCipherTextCryptoLibException">
    /// if the padding is badly formed or invalid.
    /// </exception>
    function PadCount(const input: TCryptoLibByteArray): Int32;

  end;

implementation

{ TISO7816d4Padding }

function TISO7816d4Padding.AddPadding(const input: TCryptoLibByteArray;
  inOff: Int32): Int32;
var
  added: Int32;
begin
  added := (System.Length(input) - inOff);

  input[inOff] := Byte($80);
  System.Inc(inOff);

  while (inOff < System.Length(input)) do
  begin
    input[inOff] := Byte(0);
    System.Inc(inOff);
  end;

  result := added;
end;

function TISO7816d4Padding.GetPaddingName: String;
begin
  result := 'ISO7816-4';
end;

{$IFNDEF _FIXINSIGHT_}

procedure TISO7816d4Padding.Init(const random: ISecureRandom);
begin
  // nothing to do.
end;
{$ENDIF}

function TISO7816d4Padding.PadCount(const input: TCryptoLibByteArray): Int32;
var
  count: Int32;
begin

  count := System.Length(input) - 1;

  while ((count > 0) and (input[count] = 0)) do
  begin
    System.Dec(count);
  end;

  if (input[count] <> Byte($80)) then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  end;

  result := System.Length(input) - count;

end;

end.
