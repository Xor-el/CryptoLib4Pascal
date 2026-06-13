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

unit ClpISO7816d4Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIISO7816d4Padding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'pad block corrupted';

type
  /// <summary>
  /// A padder that adds the padding according to the scheme referenced in ISO 7816-4 - scheme 2 from ISO 9797-1.
  /// </summary>
  /// <remarks>
  /// The first byte is 0x80, the rest are 0x00.
  /// </remarks>
  TISO7816d4Padding = class sealed(TInterfacedObject, IISO7816d4Padding,
    IBlockCipherPadding)
  strict private
    function GetPaddingName: String; inline;
  public
    /// <summary>
    /// Initialise the padder.
    /// </summary>
    /// <param name="ARandom">
    /// A source of randomness (ignored for ISO7816-4).
    /// </param>
    /// <remarks>
    /// For this padding scheme, the parameter is ignored.
    /// </remarks>
    procedure Init(const ARandom: ISecureRandom);
    /// <summary>
    /// Add padding to a given block.
    /// </summary>
    /// <param name="AInput">The array containing the data to be padded.</param>
    /// <param name="AInOff">The offset into the input array where padding should start.</param>
    /// <returns>The number of bytes of padding added.</returns>
    function AddPadding(const AInput: TCryptoLibByteArray; AInOff: Int32): Int32;
    /// <summary>
    /// Return the number of pad bytes found in the passed in block.
    /// </summary>
    /// <param name="AInput">The array containing the padded data.</param>
    /// <returns>The number of pad bytes.</returns>
    /// <exception cref="EInvalidCipherTextCryptoLibException">If the padding is corrupted.</exception>
    function PadCount(const AInput: TCryptoLibByteArray): Int32;
    /// <summary>
    /// The algorithm name for the padding.
    /// </summary>
    /// <value>The string <c>ISO7816-4</c>.</value>
    property PaddingName: String read GetPaddingName;
  end;

implementation

function TISO7816d4Padding.AddPadding(const AInput: TCryptoLibByteArray;
  AInOff: Int32): Int32;
var
  LAdded: Int32;
begin
  LAdded := (System.Length(AInput) - AInOff);
  AInput[AInOff] := Byte($80);
  System.Inc(AInOff);
  while (AInOff < System.Length(AInput)) do
  begin
    AInput[AInOff] := Byte(0);
    System.Inc(AInOff);
  end;
  Result := LAdded;
end;

function TISO7816d4Padding.GetPaddingName: String;
begin
  Result := 'ISO7816-4';
end;

procedure TISO7816d4Padding.Init(const ARandom: ISecureRandom);
begin
end;

function TISO7816d4Padding.PadCount(const AInput: TCryptoLibByteArray): Int32;
var
  LCount: Int32;
begin
  LCount := System.Length(AInput) - 1;
  while ((LCount > 0) and (AInput[LCount] = 0)) do
    System.Dec(LCount);
  if (AInput[LCount] <> Byte($80)) then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  Result := System.Length(AInput) - LCount;
end;

end.
