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

unit ClpAbstractBlockCipherMode;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpICipherParameters,
  ClpCheck,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';

type
  /// <summary>
  /// Shared base for the block-cipher chaining modes (CBC, CFB, OFB, ECB, SIC,
  /// OpenPGP-CFB). Owns the surface that is identical across every mode -- the
  /// underlying cipher reference, the effective block/segment size, the
  /// encrypt/decrypt direction flag, the <c>UnderlyingCipher</c> /
  /// <c>AlgorithmName</c> / <c>IsPartialBlockOkay</c> accessors, and the
  /// overflow-safe bulk bounds check -- leaving each concrete mode to supply
  /// only its algorithm-name suffix and its <c>Init</c> / <c>ProcessBlock</c> /
  /// <c>Reset</c> (and, where applicable, <c>ProcessBlocks</c>) transforms.
  /// </summary>
  TAbstractBlockCipherMode = class abstract(TInterfacedObject, IBlockCipherMode,
    IBlockCipher)

  strict protected
  var
    FCipher: IBlockCipher;
    // Effective block size in bytes: the cipher block size for CBC/ECB/SIC/PGP,
    // the feedback-segment size for CFB/OFB (set by those constructors).
    FBlockSize: Int32;
    FForEncryption: Boolean;

    /// <summary>The mode-specific suffix appended to the underlying algorithm
    /// name (e.g. <c>/CBC</c>, <c>/CFB128</c>). Computed live so segment modes
    /// can fold in their width.</summary>
    function GetModeName: String; virtual; abstract;

    function GetAlgorithmName: String; virtual;
    function GetIsPartialBlockOkay: Boolean; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

    /// <summary>
    /// Validate the buffers for a bulk request of <paramref name="ABlockCount" />
    /// blocks and return the total byte count (<c>ABlockCount * FBlockSize</c>),
    /// or 0 when <paramref name="ABlockCount" /> &lt;= 0. Overflow-safe via
    /// <see cref="TCheck" />. Raises <see cref="EDataLengthCryptoLibException" />
    /// if either range is too short.
    /// </summary>
    function CheckBlockBuffers(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32; inline;

  public
    /// <summary>Bind the mode to <paramref name="ACipher" />; the effective
    /// block size defaults to the cipher block size (segment modes override).</summary>
    constructor Create(const ACipher: IBlockCipher);

    function GetBlockSize(): Int32; virtual;
    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); virtual; abstract;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual; abstract;
    procedure Reset(); virtual; abstract;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
  end;

implementation

{ TAbstractBlockCipherMode }

constructor TAbstractBlockCipherMode.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := ACipher.GetBlockSize();
end;

function TAbstractBlockCipherMode.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + GetModeName;
end;

function TAbstractBlockCipherMode.GetBlockSize: Int32;
begin
  Result := FBlockSize;
end;

function TAbstractBlockCipherMode.GetIsPartialBlockOkay: Boolean;
begin
  Result := False;
end;

function TAbstractBlockCipherMode.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

function TAbstractBlockCipherMode.CheckBlockBuffers(
  const AInBuf: TCryptoLibByteArray; AInOff, ABlockCount: Int32;
  const AOutBuf: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if ABlockCount <= 0 then
  begin
    Result := 0;
    Exit;
  end;
  Result := ABlockCount * FBlockSize;
  TCheck.DataLength(AInBuf, AInOff, Result, SInputBufferTooShort);
  TCheck.OutputLength(AOutBuf, AOutOff, Result, SOutputBufferTooShort);
end;

end.
