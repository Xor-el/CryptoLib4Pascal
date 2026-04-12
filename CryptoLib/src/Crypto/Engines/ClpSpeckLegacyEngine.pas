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

unit ClpSpeckLegacyEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCheck,
  ClpISpeckLegacyEngine,
  ClpIBlockCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpArrayUtilities,
  ClpPlatformUtilities,
  ClpCryptoLibTypes;

resourcestring
  SSpeckLegacyEngineNotInitialised = '%s Engine not Initialised';
  SInputBuffertooShort = 'Input Buffer too Short';
  SOutputBuffertooShort = 'Output Buffer too Short';
  SInvalidArgumentEncountered = 'Invalid Argument Encountered.';
  SInvalidParameterSpeckLegacyInit =
    'Invalid Parameter Passed to SpeckLegacy Init - "%s"';
  SSpeck32LegacyInvalidKeySize =
    'Speck32Legacy requires a key of 64 bits but input was "%d" bits.';
  SSpeck48LegacyInvalidKeySize =
    'Speck48Legacy requires a key of 72 or 96 bits but input was "%d" bits.';
  SSpeck64LegacyInvalidKeySize =
    'Speck64Legacy requires a key of 96 or 128 bits but input was "%d" bits.';
  SSpeck96LegacyInvalidKeySize =
    'Speck96Legacy requires a key of 96 or 144 bits but input was "%d" bits.';
  SSpeck128LegacyInvalidKeySize =
    'Speck128Legacy requires a key of 128, 192 or 256 bits but input was "%d" bits.';

type

  /// <summary>
  /// A <b>variant</b> of the Speck family of block ciphers which treats data
  /// in big endian format for compatibility with some other <b>wrong</b>
  /// implementations .
  /// </summary>
  TSpeckLegacyEngine = class abstract(TInterfacedObject, ISpeckLegacyEngine,
    IBlockCipher)

  strict private
  var

    FInitialised, FForEncryption: Boolean;

    /// <summary>
    /// Internal method to Initialise this cipher instance.
    /// <code>true</code> for encryption, <code>false</code> for decryption.
    /// the bytes of the key to use.
    /// </summary>
    procedure EngineInit(AForEncryption: Boolean;
      const AKeyBytes: TCryptoLibByteArray); virtual;

  strict protected

  var
    FBlockSize, FWordSize, FWordSizeBits, FAlpha, FBeta, FBaseRounds,
      FRounds: Int32;

    /// <summary>
    /// Gets the algorithm name of this Speck engine.
    /// </summary>
    /// <value>
    /// the name of the Speck variant, specified to the level of the block size (e.g.
    /// <em>Speck96</em>).
    /// </value>
    function GetAlgorithmName: String; virtual;
    function GetBlockSize(): Int32; virtual;

    /// <summary>
    /// Checks whether the key size provided to the <see cref="ClpSpeckLegacyEngine|TSpeckLegacyEngine.EngineInit(Boolean,TCryptoLibByteArray)" />
    /// method is valid.
    /// </summary>
    procedure CheckKeySize(const AKeyBytes: TCryptoLibByteArray);
      virtual; abstract;

    /// <summary>
    /// Sets a key for this cipher instance, calculating the key schedule.
    /// </summary>
    procedure SetKey(const AKeyBytes: TCryptoLibByteArray); virtual; abstract;

    /// <summary>
    /// Unpack a block of data into working state prior to an
    /// encrypt/decrypt operation.
    /// </summary>
    /// <param name="ABytes">
    /// the input data.
    /// </param>
    /// <param name="AOff">
    /// the offset to begin reading the input data at.
    /// </param>
    procedure UnPackBlock(const ABytes: TCryptoLibByteArray; AOff: Int32);
      virtual; abstract;

    /// <summary>
    /// Packs the 2 word working state following an encrypt/decrypt into a
    /// byte sequence.
    /// </summary>
    /// <param name="ABytes">
    /// the output buffer.
    /// </param>
    /// <param name="AOff">
    /// the offset to begin writing the output data at.
    /// </param>
    procedure PackBlock(const ABytes: TCryptoLibByteArray; AOff: Int32);
      virtual; abstract;

    /// <summary>
    /// Encrypts the plaintext words loaded with a previous call to <see cref="ClpSpeckLegacyEngine|TSpeckLegacyEngine.UnPackBlock(TCryptoLibByteArray,Int32)" />
    /// leaving the resulting ciphertext words in the working state.
    /// </summary>
    procedure EncryptBlock(); virtual; abstract;

    /// <summary>
    /// Decrypts the ciphertext words loaded with a previous call to <see cref="ClpSpeckLegacyEngine|TSpeckLegacyEngine.UnPackBlock(TCryptoLibByteArray,Int32)" />
    /// leaving the resulting ciphertext words in the working state.
    /// </summary>

    procedure DecryptBlock(); virtual; abstract;

    /// <summary>
    /// Constructs a Speck engine.
    /// </summary>
    /// <param name="AWordSize">
    /// the size of the word to use, in bytes.
    /// </param>
    /// <param name="ABaseRounds">
    /// the base number of rounds (for a 2 word key variant) for the
    /// specified word/block size.
    /// </param>
    /// <param name="AAlpha">
    /// the alpha rotation constant to use.
    /// </param>
    /// <param name="ABeta">
    /// the beta rotation constant to use.
    /// </param>
    constructor Create(AWordSize, ABaseRounds, AAlpha, ABeta: Int32);

    /// <summary>
    /// initialise a SpeckLegacy cipher.
    /// </summary>
    /// <param name="AForEncryption">
    /// whether or not we are for encryption.
    /// </param>
    /// <param name="AParameters">
    /// the parameters required to set up the cipher.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the parameters argument is inappropriate.
    /// </exception>
    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); virtual;

    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    property AlgorithmName: String read GetAlgorithmName;

  end;

type

  /// <summary>
  /// Base class of Speck Legacy variants that fit in 32 bit Pascal Integers:
  /// SpeckLegacy32, SpeckLegacy48, SpeckLegacy64.
  /// Speck32 and Speck48 (16 and 24 bit word sizes) are implemented using masking.
  /// </summary>
  TSpeckUInt32LegacyEngine = class abstract(TSpeckLegacyEngine)

  strict private
  var

    /// <summary>
    /// The expanded key schedule for all <see cref="ClpSpeckLegacyEngine|TSpeckLegacyEngine.FRounds" />
    /// </summary>
    FK: TCryptoLibUInt32Array;

    /// <summary>
    /// The 2 words of the working state;
    /// </summary>
    FX, FY: UInt32;

    /// <summary>
    /// Rotates a word left by the specified distance. <br />The rotation is
    /// on the word size of the cipher instance, not on the full 32 bits of
    /// the UInt32.
    /// </summary>
    /// <param name="AValue">
    /// the word to rotate.
    /// </param>
    /// <param name="ADistance">
    /// the distance in bits to rotate.
    /// </param>
    /// <returns>
    /// the rotated word, which may have unmasked high (&gt; word size) bits.
    /// </returns>
    function Rotl(AValue: UInt32; ADistance: Int32): UInt32; inline;

    /// <summary>
    /// Rotates a word right by the specified distance. <br />The rotation is
    /// on the word size of the cipher instance, not on the full 32 bits of
    /// the UInt32.
    /// </summary>
    /// <param name="AValue">
    /// the word to rotate.
    /// </param>
    /// <param name="ADistance">
    /// the distance in bits to rotate.
    /// </param>
    /// <returns>
    /// the rotated word, which may have unmasked high (&gt; word size) bits.
    /// </returns>
    function Rotr(AValue: UInt32; ADistance: Int32): UInt32; inline;

    /// <summary>
    /// Read <see cref="ClpSpeckLegacyEngine|TSpeckLegacyEngine.FWordSize" /> bytes from
    /// the input data in <b>big-endian</b> order.
    /// </summary>
    /// <param name="ABytes">
    /// the data to read a word from.
    /// </param>
    /// <param name="AOff">
    /// the offset to read the word from.
    /// </param>
    /// <returns>
    /// the read word, with zeroes in any bits higher than the word size.
    /// </returns>
    function BytesToWord(const ABytes: TCryptoLibByteArray; AOff: Int32)
      : UInt32; inline;

    /// <summary>
    /// Writes <see cref="ClpSpeckLegacyEngine|TSpeckLegacyEngine.FWordSize" /> bytes
    /// into a buffer in <b>big-endian</b> order.
    /// </summary>
    /// <param name="AWord">
    /// the word to write.
    /// </param>
    /// <param name="ABytes">
    /// the buffer to write the word bytes to.
    /// </param>
    /// <param name="AOff">
    /// the offset to write the data at.
    /// </param>
    procedure WordToBytes(AWord: UInt32; const ABytes: TCryptoLibByteArray;
      AOff: Int32); inline;

  strict protected

    /// <summary>
    /// Masks all bits higher than the word size of this cipher in the
    /// supplied value.
    /// </summary>
    /// <param name="AValue">
    /// the value to mask.
    /// </param>
    /// <returns>
    /// the masked value.
    /// </returns>
    function Mask(AValue: UInt32): UInt32; virtual; abstract;

    procedure SetKey(const AKeyBytes: TCryptoLibByteArray); override;

    procedure UnPackBlock(const ABytes: TCryptoLibByteArray;
      AOff: Int32); override;

    procedure PackBlock(const ABytes: TCryptoLibByteArray; AOff: Int32); override;

    procedure EncryptBlock(); override;

    procedure DecryptBlock(); override;

    /// <summary>
    /// Constructs a SpeckLegacy cipher with &lt;= 32 bit word size, using the
    /// standard 8,3 rotation constants.
    /// </summary>
    /// <param name="AWordSize">
    /// the word size in bytes.
    /// </param>
    /// <param name="ABaseRounds">
    /// the base (for 2 word key) round count.
    /// </param>
    constructor Create(AWordSize, ABaseRounds: Int32); overload;

    /// <summary>
    /// Constructs a SpeckLegacy cipher with &lt;= 32 bit word size, using custom
    /// rotation constants.
    /// </summary>
    /// <param name="AWordSize">
    /// the word size in bytes.
    /// </param>
    /// <param name="ABaseRounds">
    /// the base (for 2 word key) round count.
    /// </param>
    /// <param name="AAlpha">
    /// the <em>alpha</em> rotation constant.
    /// </param>
    /// <param name="ABeta">
    /// the <em>beta</em> rotation constant.
    /// </param>
    constructor Create(AWordSize, ABaseRounds, AAlpha, ABeta: Int32); overload;

  end;

type

  /// <summary>
  /// Base class of Speck Legacy variants that fit in 64 bit Pascal Integers:
  /// SpeckLegacy96, SpeckLegacy128.
  /// Speck96 (48 bit word size) is implemented using masking.
  /// </summary>
  TSpeckUInt64LegacyEngine = class abstract(TSpeckLegacyEngine)

  strict private
  var

    /// <summary>
    /// The expanded key schedule for all <see cref="ClpSpeckLegacyEngine|TSpeckLegacyEngine.FRounds" />
    /// </summary>
    FK: TCryptoLibUInt64Array;

    /// <summary>
    /// The 2 words of the working state;
    /// </summary>
    FX, FY: UInt64;

    /// <summary>
    /// Rotates a word left by the specified distance. <br />The rotation is
    /// on the word size of the cipher instance, not on the full 64 bits of
    /// the UInt64.
    /// </summary>
    /// <param name="AValue">
    /// the word to rotate.
    /// </param>
    /// <param name="ADistance">
    /// the distance in bits to rotate.
    /// </param>
    /// <returns>
    /// the rotated word, which may have unmasked high (&gt; word size) bits.
    /// </returns>
    function Rotl(AValue: UInt64; ADistance: Int32): UInt64; inline;

    /// <summary>
    /// Rotates a word right by the specified distance. <br />The rotation is
    /// on the word size of the cipher instance, not on the full 64 bits of
    /// the UInt64.
    /// </summary>
    /// <param name="AValue">
    /// the word to rotate.
    /// </param>
    /// <param name="ADistance">
    /// the distance in bits to rotate.
    /// </param>
    /// <returns>
    /// the rotated word, which may have unmasked high (&gt; word size) bits.
    /// </returns>
    function Rotr(AValue: UInt64; ADistance: Int32): UInt64; inline;

    /// <summary>
    /// Read <see cref="ClpSpeckLegacyEngine|TSpeckLegacyEngine.FWordSize" /> bytes from
    /// the input data in big-endian order.
    /// </summary>
    /// <param name="ABytes">
    /// the data to read a word from.
    /// </param>
    /// <param name="AOff">
    /// the offset to read the word from.
    /// </param>
    /// <returns>
    /// the read word, with zeroes in any bits higher than the word size.
    /// </returns>
    function BytesToWord(const ABytes: TCryptoLibByteArray; AOff: Int32)
      : UInt64; inline;

    /// <summary>
    /// Writes <see cref="ClpSpeckLegacyEngine|TSpeckLegacyEngine.FWordSize" /> bytes
    /// into a buffer in big-endian order.
    /// </summary>
    /// <param name="AWord">
    /// the word to write.
    /// </param>
    /// <param name="ABytes">
    /// the buffer to write the word bytes to.
    /// </param>
    /// <param name="AOff">
    /// the offset to write the data at.
    /// </param>
    procedure WordToBytes(AWord: UInt64; const ABytes: TCryptoLibByteArray;
      AOff: Int32); inline;

  strict protected

    /// <summary>
    /// Masks all bits higher than the word size of this cipher in the
    /// supplied value.
    /// </summary>
    /// <param name="AValue">
    /// the value to mask.
    /// </param>
    /// <returns>
    /// the masked value.
    /// </returns>
    function Mask(AValue: UInt64): UInt64; virtual; abstract;

    procedure SetKey(const AKeyBytes: TCryptoLibByteArray); override;

    procedure UnPackBlock(const ABytes: TCryptoLibByteArray;
      AOff: Int32); override;

    procedure PackBlock(const ABytes: TCryptoLibByteArray; AOff: Int32); override;

    procedure EncryptBlock(); override;

    procedure DecryptBlock(); override;

    /// <summary>
    /// Constructs a SpeckLegacy cipher with &lt;= 64 bit word size, using the
    /// standard 8,3 rotation constants.
    /// </summary>
    /// <param name="AWordSize">
    /// the word size in bytes.
    /// </param>
    /// <param name="ABaseRounds">
    /// the base (for 2 word key) round count.
    /// </param>
    constructor Create(AWordSize, ABaseRounds: Int32); overload;

    /// <summary>
    /// Constructs a SpeckLegacy cipher with &lt;= 64 bit word size, using custom
    /// rotation constants.
    /// </summary>
    /// <param name="AWordSize">
    /// the word size in bytes.
    /// </param>
    /// <param name="ABaseRounds">
    /// the base (for 2 word key) round count.
    /// </param>
    /// <param name="AAlpha">
    /// the <em>alpha</em> rotation constant.
    /// </param>
    /// <param name="ABeta">
    /// the <em>beta</em> rotation constant.
    /// </param>
    constructor Create(AWordSize, ABaseRounds, AAlpha, ABeta: Int32); overload;

  end;

type

  /// <summary>
  /// Speck32Legacy: 2 byte words, 7/2 rotation constants.
  /// <p>
  /// 20 base rounds (hypothetical)
  /// </p>
  /// 64 bit key/22 rounds.
  /// </summary>
  TSpeck32LegacyEngine = class sealed(TSpeckUInt32LegacyEngine)

  strict protected
    function Mask(AValue: UInt32): UInt32; override;
    procedure CheckKeySize(const AKeyBytes: TCryptoLibByteArray); override;

  public
    constructor Create();

  end;

type

  /// <summary>
  /// Speck48Legacy: 3 byte words, 8/3 rotation constants.
  /// <p>
  /// 21 base rounds (hypothetical)
  /// </p>
  /// 72 bit key/22 rounds.
  /// 96 bit key/23 rounds.
  /// </summary>
  TSpeck48LegacyEngine = class sealed(TSpeckUInt32LegacyEngine)

  strict protected
    function Mask(AValue: UInt32): UInt32; override;
    procedure CheckKeySize(const AKeyBytes: TCryptoLibByteArray); override;

  public
    constructor Create();

  end;

type

  /// <summary>
  /// Speck64Legacy: 4 byte words, 8/3 rotation constants.
  /// <p>
  /// 25 base rounds (hypothetical)
  /// </p>
  /// 96 bit key/26 rounds.
  /// 128 bit key/27 rounds.
  /// </summary>
  TSpeck64LegacyEngine = class sealed(TSpeckUInt32LegacyEngine)

  strict protected
    function Mask(AValue: UInt32): UInt32; override;
    procedure CheckKeySize(const AKeyBytes: TCryptoLibByteArray); override;

  public
    constructor Create();

  end;

type

  /// <summary>
  /// Speck96Legacy: 6 byte words, 8/3 rotation constants.
  /// <p>
  /// 28 base rounds
  /// </p>
  /// 96 bit key/28 rounds.
  /// 144 bit key/29 rounds.
  /// </summary>
  TSpeck96LegacyEngine = class sealed(TSpeckUInt64LegacyEngine)

  strict protected
    function Mask(AValue: UInt64): UInt64; override;
    procedure CheckKeySize(const AKeyBytes: TCryptoLibByteArray); override;

  public
    constructor Create();

  end;

type

  /// <summary>
  /// Speck128Legacy: 8 byte words, 8/3 rotation constants.
  /// <p>
  /// 32 base rounds
  /// </p>
  /// 128 bit key/32 rounds.
  /// 192 bit key/33 rounds.
  /// 256 bit key/34 rounds.
  /// </summary>
  TSpeck128LegacyEngine = class sealed(TSpeckUInt64LegacyEngine)

  strict protected
    function Mask(AValue: UInt64): UInt64; override;
    procedure CheckKeySize(const AKeyBytes: TCryptoLibByteArray); override;

  public
    constructor Create();

  end;

implementation

{ TSpeckLegacyEngine }

constructor TSpeckLegacyEngine.Create(AWordSize, ABaseRounds, AAlpha, ABeta: Int32);
begin
  Inherited Create();
  FWordSize := AWordSize;
  FBaseRounds := ABaseRounds;
  FRounds := ABaseRounds;
  FBlockSize := AWordSize * 2;
  FWordSizeBits := AWordSize * 8;
  FAlpha := AAlpha;
  FBeta := ABeta;
end;

function TSpeckLegacyEngine.GetBlockSize: Int32;
begin
  Result := FBlockSize;
end;

procedure TSpeckLegacyEngine.EngineInit(AForEncryption: Boolean;
  const AKeyBytes: TCryptoLibByteArray);
begin
  FForEncryption := AForEncryption;
  CheckKeySize(AKeyBytes);
  SetKey(AKeyBytes);
  FInitialised := True;
end;

function TSpeckLegacyEngine.GetAlgorithmName: String;
begin
  Result := Format('SpeckLegacy%d', [FBlockSize * 8]);
end;

procedure TSpeckLegacyEngine.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParameter: IKeyParameter;
begin
  if not Supports(AParameters, IKeyParameter, LKeyParameter) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt
      (@SInvalidParameterSpeckLegacyInit, [TPlatformUtilities.GetTypeName(AParameters as TObject)]);
  end;
  EngineInit(AForEncryption, LKeyParameter.GetKey());
end;

function TSpeckLegacyEngine.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if (not FInitialised) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt
      (@SSpeckLegacyEngineNotInitialised, [AlgorithmName]);
  end;

  TCheck.DataLength((AInOff + FBlockSize) > System.Length(AInput),
    SInputBuffertooShort);
  TCheck.DataLength((AOutOff + FBlockSize) > System.Length(AOutput),
    SOutputBuffertooShort);

  UnPackBlock(AInput, AInOff);
  if (FForEncryption) then
  begin
    EncryptBlock();
  end
  else
  begin
    DecryptBlock();
  end;
  PackBlock(AOutput, AOutOff);

  Result := FBlockSize;
end;

{ TSpeckUInt32LegacyEngine }

function TSpeckUInt32LegacyEngine.Rotl(AValue: UInt32; ADistance: Int32): UInt32;
begin
  Result := ((AValue shl ADistance) or (AValue shr (FWordSizeBits - ADistance)));
end;

function TSpeckUInt32LegacyEngine.Rotr(AValue: UInt32; ADistance: Int32): UInt32;
begin
  Result := ((AValue shr ADistance) or (AValue shl (FWordSizeBits - ADistance)));
end;

function TSpeckUInt32LegacyEngine.BytesToWord(const ABytes: TCryptoLibByteArray;
  AOff: Int32): UInt32;
var
  LIndex: Int32;
begin
  TCheck.DataLength((AOff + FWordSize) > System.Length(ABytes),
    SInvalidArgumentEncountered);

  LIndex := AOff;
  Result := (ABytes[LIndex]);
  System.Inc(LIndex);
  Result := (Result shl 8) or (ABytes[LIndex]);
  System.Inc(LIndex);
  if (FWordSize > 2) then
  begin
    Result := (Result shl 8) or (ABytes[LIndex]);
    System.Inc(LIndex);
    if (FWordSize > 3) then
    begin
      Result := (Result shl 8) or (ABytes[LIndex]);
    end;
  end;

end;

procedure TSpeckUInt32LegacyEngine.WordToBytes(AWord: UInt32;
  const ABytes: TCryptoLibByteArray; AOff: Int32);
var
  LIndex: Int32;
begin
  TCheck.DataLength((AOff + FWordSize) > System.Length(ABytes),
    SInvalidArgumentEncountered);

  LIndex := AOff + FWordSize - 1;
  ABytes[LIndex] := Byte(AWord);
  System.Dec(LIndex);
  ABytes[LIndex] := Byte(AWord shr 8);
  System.Dec(LIndex);
  if (FWordSize > 2) then
  begin
    ABytes[LIndex] := Byte(AWord shr 16);
    System.Dec(LIndex);
    if (FWordSize > 3) then
    begin
      ABytes[LIndex] := Byte(AWord shr 24);
    end;
  end;

end;

constructor TSpeckUInt32LegacyEngine.Create(AWordSize, ABaseRounds: Int32);
begin
  Create(AWordSize, ABaseRounds, 8, 3);
end;

constructor TSpeckUInt32LegacyEngine.Create(AWordSize, ABaseRounds, AAlpha,
  ABeta: Int32);
begin
  inherited Create(AWordSize, ABaseRounds, AAlpha, ABeta);
end;

procedure TSpeckUInt32LegacyEngine.EncryptBlock;
var
  LX, LY: UInt32;
  LR: Int32;
begin
  LX := FX;
  LY := FY;

  for LR := 0 to System.Pred(FRounds) do
  begin
    LX := Mask((Rotr(LX, FAlpha) + LY) xor FK[LR]);
    LY := Mask(Rotl(LY, FBeta) xor LX);
  end;

  FX := LX;
  FY := LY;
end;

procedure TSpeckUInt32LegacyEngine.DecryptBlock;
var
  LX, LY: UInt32;
  LR: Int32;
begin
  LX := FX;
  LY := FY;

  for LR := System.Pred(FRounds) downto 0 do
  begin
    LY := Mask(Rotr(LX xor LY, FBeta));
    LX := Mask(Rotl(Mask((LX xor FK[LR]) - LY), FAlpha));
  end;

  FX := LX;
  FY := LY;
end;

procedure TSpeckUInt32LegacyEngine.PackBlock(const ABytes: TCryptoLibByteArray;
  AOff: Int32);
begin
  WordToBytes(FY, ABytes, AOff + FWordSize);
  WordToBytes(FX, ABytes, AOff);
end;

procedure TSpeckUInt32LegacyEngine.UnPackBlock(const ABytes: TCryptoLibByteArray;
  AOff: Int32);
begin
  FY := BytesToWord(ABytes, AOff + FWordSize);
  FX := BytesToWord(ABytes, AOff);
end;

procedure TSpeckUInt32LegacyEngine.SetKey(const AKeyBytes: TCryptoLibByteArray);
var
  LKeyWords, LI, LLw: Int32;
  LL: TCryptoLibUInt32Array;
begin
  // Determine number of key words m
  LKeyWords := System.Length(AKeyBytes) div FWordSize;

  // Number of rounds is increased by 1 for each key word > 2
  FRounds := FBaseRounds + (LKeyWords - 2);
  System.SetLength(FK, FRounds);

  // Load k[0]
  FK[0] := BytesToWord(AKeyBytes, (LKeyWords - 1) * FWordSize);

  // Load l[m-2]...l[0], leave space for l[m-1] in key expansion
  System.SetLength(LL, LKeyWords);

  for LI := 0 to System.Pred(LKeyWords - 1) do
  begin
    LL[LI] := BytesToWord(AKeyBytes, (LKeyWords - LI - 2) * FWordSize);
  end;
  // Key expansion using round function over l[m-2]...l[0],k[0] with round number as key
  for LI := 0 to System.Pred(FRounds - 1) do
  begin
    LLw := (LI + LKeyWords - 1) mod LKeyWords;
    LL[LLw] := Mask((Rotr(LL[LI mod LKeyWords], FAlpha) + FK[LI]) xor UInt32(LI));
    FK[LI + 1] := Mask(Rotl(FK[LI], FBeta) xor LL[LLw]);

  end;

  TArrayUtilities.Fill<Byte>(AKeyBytes, 0, System.Length(AKeyBytes), Byte(0));
end;

{ TSpeckUInt64LegacyEngine }

function TSpeckUInt64LegacyEngine.Rotl(AValue: UInt64; ADistance: Int32): UInt64;
begin
  Result := ((AValue shl ADistance) or (AValue shr (FWordSizeBits - ADistance)));
end;

function TSpeckUInt64LegacyEngine.Rotr(AValue: UInt64; ADistance: Int32): UInt64;
begin
  Result := ((AValue shr ADistance) or (AValue shl (FWordSizeBits - ADistance)));
end;

function TSpeckUInt64LegacyEngine.BytesToWord(const ABytes: TCryptoLibByteArray;
  AOff: Int32): UInt64;
var
  LIndex: Int32;
begin
  TCheck.DataLength((AOff + FWordSize) > System.Length(ABytes),
    SInvalidArgumentEncountered);

  LIndex := AOff;
  Result := (ABytes[LIndex]);
  System.Inc(LIndex);
  Result := (Result shl 8) or (ABytes[LIndex]);
  System.Inc(LIndex);
  Result := (Result shl 8) or (ABytes[LIndex]);
  System.Inc(LIndex);
  Result := (Result shl 8) or (ABytes[LIndex]);
  System.Inc(LIndex);
  Result := (Result shl 8) or (ABytes[LIndex]);
  System.Inc(LIndex);
  Result := (Result shl 8) or (ABytes[LIndex]);
  System.Inc(LIndex);
  if (FWordSize = 8) then
  begin
    Result := (Result shl 8) or (ABytes[LIndex]);
    System.Inc(LIndex);
    Result := (Result shl 8) or (ABytes[LIndex]);
  end;
end;

procedure TSpeckUInt64LegacyEngine.WordToBytes(AWord: UInt64;
  const ABytes: TCryptoLibByteArray; AOff: Int32);
var
  LIndex: Int32;
begin
  TCheck.DataLength((AOff + FWordSize) > System.Length(ABytes),
    SInvalidArgumentEncountered);

  LIndex := AOff + FWordSize - 1;
  ABytes[LIndex] := Byte(AWord);
  System.Dec(LIndex);
  ABytes[LIndex] := Byte(AWord shr 8);
  System.Dec(LIndex);
  ABytes[LIndex] := Byte(AWord shr 16);
  System.Dec(LIndex);
  ABytes[LIndex] := Byte(AWord shr 24);
  System.Dec(LIndex);
  ABytes[LIndex] := Byte(AWord shr 32);
  System.Dec(LIndex);
  ABytes[LIndex] := Byte(AWord shr 40);
  System.Dec(LIndex);
  if (FWordSize = 8) then
  begin
    ABytes[LIndex] := Byte(AWord shr 48);
    System.Dec(LIndex);
    ABytes[LIndex] := Byte(AWord shr 56);
  end;

end;

constructor TSpeckUInt64LegacyEngine.Create(AWordSize, ABaseRounds: Int32);
begin
  Create(AWordSize, ABaseRounds, 8, 3);
end;

constructor TSpeckUInt64LegacyEngine.Create(AWordSize, ABaseRounds, AAlpha,
  ABeta: Int32);
begin
  Inherited Create(AWordSize, ABaseRounds, AAlpha, ABeta);
end;

procedure TSpeckUInt64LegacyEngine.EncryptBlock;
var
  LX, LY: UInt64;
  LR: Int32;
begin
  LX := FX;
  LY := FY;

  for LR := 0 to System.Pred(FRounds) do
  begin
    LX := Mask((Rotr(LX, FAlpha) + LY) xor FK[LR]);
    LY := Mask(Rotl(LY, FBeta) xor LX);
  end;

  FX := LX;
  FY := LY;
end;

procedure TSpeckUInt64LegacyEngine.DecryptBlock;
var
  LX, LY: UInt64;
  LR: Int32;
begin
  LX := FX;
  LY := FY;

  for LR := System.Pred(FRounds) downto 0 do
  begin
    LY := Mask(Rotr(LX xor LY, FBeta));
    LX := Mask(Rotl(Mask((LX xor FK[LR]) - LY), FAlpha));
  end;

  FX := LX;
  FY := LY;

end;

procedure TSpeckUInt64LegacyEngine.PackBlock(const ABytes: TCryptoLibByteArray;
  AOff: Int32);
begin
  WordToBytes(FY, ABytes, AOff + FWordSize);
  WordToBytes(FX, ABytes, AOff);
end;

procedure TSpeckUInt64LegacyEngine.UnPackBlock(const ABytes: TCryptoLibByteArray;
  AOff: Int32);
begin
  FY := BytesToWord(ABytes, AOff + FWordSize);
  FX := BytesToWord(ABytes, AOff);
end;

procedure TSpeckUInt64LegacyEngine.SetKey(const AKeyBytes: TCryptoLibByteArray);
var
  LKeyWords, LI, LLw: Int32;
  LL: TCryptoLibUInt64Array;
begin
  // Determine number of key words m
  LKeyWords := System.Length(AKeyBytes) div FWordSize;

  // Number of rounds is increased by 1 for each key word > 2
  FRounds := FBaseRounds + (LKeyWords - 2);
  System.SetLength(FK, FRounds);

  // Load k[0]
  FK[0] := BytesToWord(AKeyBytes, (LKeyWords - 1) * FWordSize);

  // Load l[m-2]...l[0], leave space for l[m-1] in key expansion
  System.SetLength(LL, LKeyWords);

  for LI := 0 to System.Pred(LKeyWords - 1) do
  begin
    LL[LI] := BytesToWord(AKeyBytes, (LKeyWords - LI - 2) * FWordSize);
  end;
  // Key expansion using round function over l[m-2]...l[0],k[0] with round number as key
  for LI := 0 to System.Pred(FRounds - 1) do
  begin
    LLw := (LI + LKeyWords - 1) mod LKeyWords;
    LL[LLw] := Mask((Rotr(LL[LI mod LKeyWords], FAlpha) + FK[LI]) xor UInt64(LI));
    FK[LI + 1] := Mask(Rotl(FK[LI], FBeta) xor LL[LLw]);

  end;

  TArrayUtilities.Fill<Byte>(AKeyBytes, 0, System.Length(AKeyBytes), Byte(0));
end;

{ TSpeck32LegacyEngine }

constructor TSpeck32LegacyEngine.Create;
begin
  inherited Create(2, 20, 7, 2);
end;

function TSpeck32LegacyEngine.Mask(AValue: UInt32): UInt32;
begin
  Result := (AValue and $FFFF);
end;

procedure TSpeck32LegacyEngine.CheckKeySize(const AKeyBytes
  : TCryptoLibByteArray);
var
  LKeyBytesSize: Int32;
begin
  LKeyBytesSize := System.Length(AKeyBytes);
  if (LKeyBytesSize <> 8) then
  begin
    TArrayUtilities.Fill<Byte>(AKeyBytes, 0, System.Length(AKeyBytes), Byte(0));
    raise EArgumentCryptoLibException.CreateResFmt
      (@SSpeck32LegacyInvalidKeySize, [LKeyBytesSize * 8]);
  end;
end;

{ TSpeck48LegacyEngine }

constructor TSpeck48LegacyEngine.Create;
begin
  inherited Create(3, 21);
end;

function TSpeck48LegacyEngine.Mask(AValue: UInt32): UInt32;
begin
  Result := (AValue and $FFFFFF);
end;

procedure TSpeck48LegacyEngine.CheckKeySize(const AKeyBytes
  : TCryptoLibByteArray);
var
  LKeyBytesSize: Int32;
begin
  LKeyBytesSize := System.Length(AKeyBytes);
  if not(LKeyBytesSize in [9, 12]) then
  begin
    TArrayUtilities.Fill<Byte>(AKeyBytes, 0, System.Length(AKeyBytes), Byte(0));
    raise EArgumentCryptoLibException.CreateResFmt
      (@SSpeck48LegacyInvalidKeySize, [LKeyBytesSize * 8]);
  end;
end;

{ TSpeck64LegacyEngine }

constructor TSpeck64LegacyEngine.Create;
begin
  inherited Create(4, 25);
end;

function TSpeck64LegacyEngine.Mask(AValue: UInt32): UInt32;
begin
  Result := AValue;
end;

procedure TSpeck64LegacyEngine.CheckKeySize(const AKeyBytes
  : TCryptoLibByteArray);
var
  LKeyBytesSize: Int32;
begin
  LKeyBytesSize := System.Length(AKeyBytes);
  if not(LKeyBytesSize in [12, 16]) then
  begin
    TArrayUtilities.Fill<Byte>(AKeyBytes, 0, System.Length(AKeyBytes), Byte(0));
    raise EArgumentCryptoLibException.CreateResFmt
      (@SSpeck64LegacyInvalidKeySize, [LKeyBytesSize * 8]);
  end;
end;

{ TSpeck96LegacyEngine }

constructor TSpeck96LegacyEngine.Create;
begin
  inherited Create(6, 28);
end;

function TSpeck96LegacyEngine.Mask(AValue: UInt64): UInt64;
begin
  Result := (AValue and $0000FFFFFFFFFFFF);
end;

procedure TSpeck96LegacyEngine.CheckKeySize(const AKeyBytes
  : TCryptoLibByteArray);
var
  LKeyBytesSize: Int32;
begin
  LKeyBytesSize := System.Length(AKeyBytes);
  if not(LKeyBytesSize in [12, 18]) then
  begin
    TArrayUtilities.Fill<Byte>(AKeyBytes, 0, System.Length(AKeyBytes), Byte(0));
    raise EArgumentCryptoLibException.CreateResFmt
      (@SSpeck96LegacyInvalidKeySize, [LKeyBytesSize * 8]);
  end;
end;

{ TSpeck128LegacyEngine }

constructor TSpeck128LegacyEngine.Create;
begin
  Inherited Create(8, 32);
end;

function TSpeck128LegacyEngine.Mask(AValue: UInt64): UInt64;
begin
  Result := AValue;
end;

procedure TSpeck128LegacyEngine.CheckKeySize(const AKeyBytes
  : TCryptoLibByteArray);
var
  LKeyBytesSize: Int32;
begin
  LKeyBytesSize := System.Length(AKeyBytes);
  if not(LKeyBytesSize in [16, 24, 32]) then
  begin
    TArrayUtilities.Fill<Byte>(AKeyBytes, 0, System.Length(AKeyBytes), Byte(0));
    raise EArgumentCryptoLibException.CreateResFmt
      (@SSpeck128LegacyInvalidKeySize, [LKeyBytesSize * 8]);
  end;
end;

end.
