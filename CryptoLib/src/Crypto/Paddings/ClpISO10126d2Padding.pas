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

unit ClpISO10126d2Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIISO10126d2Padding,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'Pad Block Corrupted';

type

  /// <summary>
  /// A padder that adds ISO10126-2 padding to a block.
  /// </summary>
  TISO10126d2Padding = class sealed(TInterfacedObject, IISO10126d2Padding,
    IBlockCipherPadding)

  strict private

  var
    FRandom: ISecureRandom;
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

{ TISO10126d2Padding }

function TISO10126d2Padding.AddPadding(const input: TCryptoLibByteArray;
  inOff: Int32): Int32;
var
  code: Byte;
begin
  code := Byte(System.Length(input) - inOff);

  while (inOff < (System.Length(input) - 1)) do
  begin
    input[inOff] := Byte(FRandom.NextInt32);
    System.Inc(inOff);
  end;

  input[inOff] := code;

  result := code;
end;

function TISO10126d2Padding.GetPaddingName: String;
begin
  result := 'ISO10126-2';
end;

procedure TISO10126d2Padding.Init(const random: ISecureRandom);
begin
  if random <> Nil then
  begin
    FRandom := random;
  end
  else
  begin
    FRandom := TSecureRandom.Create();
  end;
end;

function TISO10126d2Padding.PadCount(const input: TCryptoLibByteArray): Int32;
var
  count: Int32;
begin

  count := input[System.Length(input) - 1] and $FF;

  if (count > System.Length(input)) then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  end;

  result := count;

end;

end.
