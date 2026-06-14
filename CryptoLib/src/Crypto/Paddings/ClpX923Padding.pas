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

unit ClpX923Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIX923Padding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'pad block corrupted';

type
  /// <summary>
  /// A padder that adds X9.23 padding to a block.
  /// </summary>
  /// <remarks>
  /// If a <see cref="ISecureRandom"/> is passed in, random padding is used; otherwise, the block is padded
  /// with zeros.
  /// </remarks>
  TX923Padding = class sealed(TInterfacedObject, IX923Padding,
    IBlockCipherPadding)
  strict private
    FRandom: ISecureRandom;
    function GetPaddingName: String; inline;
  public
    /// <summary>
    /// Initialise the padder.
    /// </summary>
    /// <param name="ARandom">
    /// A source of randomness.
    /// </param>
    /// <remarks>
    /// If <paramref name="ARandom"/> is nil, zero padding is used; otherwise, the block is padded with
    /// random bytes.
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
    /// <value>The string <c>X9.23</c>.</value>
    property PaddingName: String read GetPaddingName;
  end;

implementation

function TX923Padding.AddPadding(const AInput: TCryptoLibByteArray;
  AInOff: Int32): Int32;
var
  LCode: Byte;
begin
  LCode := Byte(System.Length(AInput) - AInOff);
  while (AInOff < (System.Length(AInput) - 1)) do
  begin
    if (FRandom = nil) then
      AInput[AInOff] := 0
    else
      AInput[AInOff] := Byte(FRandom.NextInt32);
    System.Inc(AInOff);
  end;
  AInput[AInOff] := LCode;
  Result := LCode;
end;

function TX923Padding.GetPaddingName: String;
begin
  Result := 'X9.23';
end;

procedure TX923Padding.Init(const ARandom: ISecureRandom);
begin
  FRandom := ARandom;
end;

function TX923Padding.PadCount(const AInput: TCryptoLibByteArray): Int32;
var
  LCount: Int32;
begin
  LCount := AInput[System.Length(AInput) - 1] and $FF;
  if (LCount > System.Length(AInput)) then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  Result := LCount;
end;

end.
