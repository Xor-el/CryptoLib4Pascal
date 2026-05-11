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

unit ClpOfbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIOfbBlockCipher,
  ClpICipherParameters,
  ClpCipherModeParameterUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer Too Short';
  SOutputBufferTooShort = 'Output Buffer Too Short';

type
  /// <summary>
  /// Implements Output-FeedBack (OFB) mode on top of a <see cref="IBlockCipher"/>.
  /// </summary>
  /// <remarks>
  /// <see cref="IsPartialBlockOkay"/> is True (stream-style output).
  /// <c>AForEncryption</c> on <see cref="Init"/> does not change keystream scheduling; encrypt and decrypt XOR the same keystream,
  /// matching classic OFB semantics.
  /// </remarks>
  TOfbBlockCipher = class sealed(TInterfacedObject, IOfbBlockCipher,
    IBlockCipherMode, IBlockCipher)

  strict private
  var
    FIV, FOfbV, FOfbOutV: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;

  strict protected
    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;
    function GetUnderlyingCipher(): IBlockCipher; inline;

  public
    /// <summary>
    /// Basic constructor.
    /// </summary>
    /// <param name="ACipher">Block cipher supplying the keystream.</param>
    /// <param name="ABlockSize">OFB width in bits (must be a multiple of 8).</param>
    constructor Create(const ACipher: IBlockCipher; ABlockSize: Int32);
    /// <summary>
    /// Initialise keystream generator state and optionally the IV.
    /// </summary>
    /// <param name="AForEncryption">Ignored by OFB (included for interface uniformity).</param>
    /// <param name="AParameters">Key wrapped in <see cref="IParametersWithIV"/> for IV extraction; IV is copied into internal state via <see cref="TCipherModeParameterUtilities.TryUnwrapIv"/> (right-aligned / zero padded when shorter than block).</param>
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    /// <summary>The OFB segment size in bytes.</summary>
    function GetBlockSize(): Int32; inline;
    /// <summary>Xor one OFB segment with the keystream.</summary>
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
    /// <summary>Reset keystream pipeline to the captured IV layout.</summary>
    procedure Reset(); inline;

    /// <summary>The underlying <see cref="IBlockCipher"/>.</summary>
    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
    /// <summary>Returns True (partial blocks allowed).</summary>
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
  end;

implementation

{ TOfbBlockCipher }

constructor TOfbBlockCipher.Create(const ACipher: IBlockCipher;
  ABlockSize: Int32);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := ABlockSize div 8;

  System.SetLength(FIV, FCipher.GetBlockSize());
  System.SetLength(FOfbV, FCipher.GetBlockSize());
  System.SetLength(FOfbOutV, FCipher.GetBlockSize());
end;

procedure TOfbBlockCipher.Reset;
begin
  System.Move(FIV[0], FOfbV[0], System.Length(FIV));
end;

function TOfbBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/OFB' + IntToStr(FBlockSize * 8);
end;

function TOfbBlockCipher.GetBlockSize: Int32;
begin
  Result := FBlockSize;
end;

function TOfbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := True;
end;

function TOfbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TOfbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
begin
  TCipherModeParameterUtilities.TryUnwrapIv(AParameters, FIV, LParameters);

  Reset();
  if (LParameters <> nil) then
    FCipher.Init(True, LParameters);
end;

function TOfbBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LCount: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FOfbV, 0, FOfbOutV, 0);

  for LI := 0 to System.Pred(FBlockSize) do
    AOutput[AOutOff + LI] := Byte(FOfbOutV[LI] xor AInput[AInOff + LI]);

  LCount := (System.Length(FOfbV) - FBlockSize) * System.SizeOf(Byte);
  if LCount > 0 then
    System.Move(FOfbV[FBlockSize], FOfbV[0], LCount);

  System.Move(FOfbOutV[0], FOfbV[(System.Length(FOfbV) - FBlockSize)],
    FBlockSize * System.SizeOf(Byte));

  Result := FBlockSize;
end;

end.
