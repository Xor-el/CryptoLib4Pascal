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

unit ClpPkcs7Padding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipherPadding,
  ClpIPkcs7Padding,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SCorruptedPadBlock = 'pad block corrupted';

type
  /// <summary>
  /// A padder that adds PKCS7/PKCS5 padding to a block.
  /// </summary>
  TPkcs7Padding = class sealed(TInterfacedObject, IPkcs7Padding,
    IBlockCipherPadding)
  strict private
    function GetPaddingName: String; inline;
  public
    /// <summary>
    /// Initialise the padder.
    /// </summary>
    /// <param name="ARandom">
    /// A source of randomness (ignored for PKCS7).
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
    /// <value>The string <c>PKCS7</c>.</value>
    property PaddingName: String read GetPaddingName;
  end;

implementation

function TPkcs7Padding.AddPadding(const AInput: TCryptoLibByteArray;
  AInOff: Int32): Int32;
var
  LCode: Byte;
begin
  LCode := Byte(System.Length(AInput) - AInOff);
  while (AInOff < System.Length(AInput)) do
  begin
    AInput[AInOff] := LCode;
    System.Inc(AInOff);
  end;
  Result := LCode;
end;

function TPkcs7Padding.GetPaddingName: String;
begin
  Result := 'PKCS7';
end;

procedure TPkcs7Padding.Init(const ARandom: ISecureRandom);
begin
end;

function TPkcs7Padding.PadCount(const AInput: TCryptoLibByteArray): Int32;
var
  LCountAsByte: Byte;
  LCount, LI: Int32;
  LFailed: Boolean;
begin
  LCount := AInput[System.Length(AInput) - 1] and $FF;
  LCountAsByte := Byte(LCount);
  LFailed := ((LCount > System.Length(AInput)) or (LCount = 0));
  for LI := 0 to System.Pred(System.Length(AInput)) do
    LFailed := LFailed or ((System.Length(AInput) - LI <= LCount) and
      (AInput[LI] <> LCountAsByte));
  if (LFailed) then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SCorruptedPadBlock);
  Result := LCount;
end;

end.
