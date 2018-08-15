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

unit ClpPkcs7Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIPkcs7Padding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'Pad Block Corrupted';

type
  TPkcs7Padding = class sealed(TInterfacedObject, IPkcs7Padding,
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

{ TPkcs7Padding }

function TPkcs7Padding.AddPadding(const input: TCryptoLibByteArray;
  inOff: Int32): Int32;
var
  code: Byte;
begin
  code := Byte(System.Length(input) - inOff);

  while (inOff < System.Length(input)) do
  begin
    input[inOff] := code;
    System.Inc(inOff);
  end;

  result := code;
end;

function TPkcs7Padding.GetPaddingName: String;
begin
  result := 'PKCS7';
end;

{$IFNDEF _FIXINSIGHT_}

procedure TPkcs7Padding.Init(const random: ISecureRandom);
begin
  // nothing to do.
end;
{$ENDIF}

function TPkcs7Padding.PadCount(const input: TCryptoLibByteArray): Int32;
var
  countAsByte: Byte;
  count, i: Int32;
  failed: Boolean;
begin
  // countAsByte := input[System.Length(input) - 1];
  // count := countAsByte;
  //
  // if ((count < 1) or (count > System.Length(input))) then
  // begin
  // raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  // end;
  //
  // for i := 2 to count do
  // begin
  // if (input[System.Length(input) - i] <> countAsByte) then
  // begin
  // raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  // end;
  // end;
  //
  // result := count;

  count := input[System.Length(input) - 1] and $FF;
  countAsByte := Byte(count);

  // constant time version
  failed := ((count > System.Length(input)) or (count = 0));

  for i := 0 to System.Pred(System.Length(input)) do
  begin
    failed := failed or ((System.Length(input) - i <= count) and
      (input[i] <> countAsByte));
  end;

  if (failed) then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  end;

  result := count;

end;

end.
