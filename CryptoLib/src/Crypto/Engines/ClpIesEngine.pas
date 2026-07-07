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

unit ClpIesEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpIMac,
  ClpIIesEngine,
  ClpIBasicAgreement,
  ClpIDerivationFunction,
  ClpIBufferedBlockCipher,
  ClpICipherParameters,
  ClpIIesParameters,
  ClpIEphemeralKeyPairGenerator,
  ClpIAsymmetricKeyParameter,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIKeyParser,
  ClpIEphemeralKeyPair,
  ClpKdfParameters,
  ClpIKdfParameters,
  ClpPack,
  ClpArrayUtilities,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpByteUtilities,
  ClpCryptoLibTypes;

resourcestring
  SErrorRecoveringEphemeralPublicKey =
    'Unable to Recover Ephemeral Public Key: "%s"';
  SInvalidCipherTextLength =
    'Length of Input Must be Greater than the MAC and V Combined';
  SInvalidMAC = 'Invalid MAC.';
  SIesParametersMustSupportIIesWithCipherParameters = 'IES parameters must support IIesWithCipherParameters for block cipher mode';
  SParametersMustSupportIesParameters = 'parameters must support IIesParameters';

type
  /// <summary>
  /// Support class for constructing integrated encryption ciphers for doing
  /// basic message exchanges on top of key agreement ciphers. <br />Follows
  /// the description given in IEEE Std 1363a.
  /// </summary>
  TIesEngine = class(TInterfacedObject, IIesEngine)

  strict private
  var
    FParam: IIesParameters;

    // as described in Shroup's paper( ch 10, pg 20) and P1363a
    function GetLengthTag(const AP2: TCryptoLibByteArray)
      : TCryptoLibByteArray; inline;

    procedure ExtractParams(const AParams: ICipherParameters); inline;

    function SimilarMacCompute(const AArgOne, AArgTwo: TCryptoLibByteArray)
      : TCryptoLibByteArray; inline;

  strict protected

  var
    FAgree: IBasicAgreement;
    FKdf: IDerivationFunction;
    FMac: IMac;
    FCipher: IBufferedBlockCipher;
    FV, FIV: TCryptoLibByteArray;
    FForEncryption: Boolean;
    FPrivParam, FPubParam: ICipherParameters;
    FKeyPairGenerator: IEphemeralKeyPairGenerator;
    FKeyParser: IKeyParser;

    function GetCipher: IBufferedBlockCipher; inline;
    function GetMac: IMac; inline;
    procedure SetupBlockCipherAndMacKeyBytes(out AK1,
      AK2: TCryptoLibByteArray); inline;

    function EncryptBlock(const AIn: TCryptoLibByteArray; AInOff, AInLen: Int32)
      : TCryptoLibByteArray; virtual;

    function DecryptBlock(const AInEnc: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray; virtual;

  public

    /// <summary>
    /// Set up for use with stream mode, where the key derivation function is
    /// used to provide a stream of bytes to xor with the message.
    /// </summary>
    /// <remarks>
    /// <b>Security note:</b> when this engine is initialised with static keys on both sides (the
    /// Init overload that supplies no ephemeral component) the key-derivation input is the same
    /// for every message, so the stream-mode keystream is identical from message to message -
    /// encrypting more than one message under a given key pair is a many-time pad and leaks
    /// plaintext relationships. Use the ephemeral sender-key initialisation (the standard ECIES
    /// mode) for messages that must remain confidential; the static-static mode is effectively
    /// deterministic encryption.
    /// </remarks>
    /// <param name="AAgree">
    /// the key agreement used as the basis for the encryption
    /// </param>
    /// <param name="AKdf">
    /// the key derivation function used for byte generation
    /// </param>
    /// <param name="AMac">
    /// the message authentication code generator for the message
    /// </param>
    constructor Create(const AAgree: IBasicAgreement;
      const AKdf: IDerivationFunction; const AMac: IMac); overload;

    /// <summary>
    /// Set up for use in conjunction with a block cipher to handle the <br />
    /// message. It is <b>strongly</b> recommended that the cipher is not
    /// in ECB mode.
    /// </summary>
    /// <param name="AAgree">
    /// the key agreement used as the basis for the encryption
    /// </param>
    /// <param name="AKdf">
    /// the key derivation function used for byte generation
    /// </param>
    /// <param name="AMac">
    /// the message authentication code generator for the message
    /// </param>
    /// <param name="ACipher">
    /// the cipher to used for encrypting the message
    /// </param>
    constructor Create(const AAgree: IBasicAgreement;
      const AKdf: IDerivationFunction; const AMac: IMac;
      const ACipher: IBufferedBlockCipher); overload;

    /// <summary>
    /// Initialise the encryptor/decryptor.
    /// </summary>
    /// <param name="AForEncryption">
    /// whether or not this is encryption/decryption.
    /// </param>
    /// <param name="APrivParam">
    /// our private key parameters
    /// </param>
    /// <param name="APubParam">
    /// the recipient's/sender's public key parameters
    /// </param>
    /// <param name="AParams">
    /// encoding and derivation parameters, may be wrapped to include an IV
    /// for an underlying block cipher.
    /// </param>
    procedure Init(AForEncryption: Boolean; const APrivParam, APubParam,
      AParams: ICipherParameters); overload;

    /// <summary>
    /// Initialise the encryptor.
    /// </summary>
    /// <param name="APublicKey">
    /// the recipient's/sender's public key parameters
    /// </param>
    /// <param name="AParams">
    /// encoding and derivation parameters, may be wrapped to include an IV
    /// for an underlying block cipher.
    /// </param>
    /// <param name="AEphemeralKeyPairGenerator">
    /// the ephemeral key pair generator to use.
    /// </param>
    procedure Init(const APublicKey: IAsymmetricKeyParameter;
      const AParams: ICipherParameters;
      const AEphemeralKeyPairGenerator: IEphemeralKeyPairGenerator); overload;

    /// <summary>
    /// Initialise the decryptor.
    /// </summary>
    /// <param name="APrivateKey">
    /// the recipient's private key.
    /// </param>
    /// <param name="AParams">
    /// encoding and derivation parameters, may be wrapped to include an IV
    /// for an underlying block cipher.
    /// </param>
    /// <param name="APublicKeyParser">
    /// the parser for reading the ephemeral public key.
    /// </param>
    procedure Init(const APrivateKey: IAsymmetricKeyParameter;
      const AParams: ICipherParameters;
      const APublicKeyParser: IKeyParser); overload;

    function ProcessBlock(const AIn: TCryptoLibByteArray; AInOff, AInLen: Int32)
      : TCryptoLibByteArray; virtual;

    property Cipher: IBufferedBlockCipher read GetCipher;
    property Mac: IMac read GetMac;

  end;

implementation

{ TIESEngine }

function TIesEngine.GetLengthTag(const AP2: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  System.SetLength(Result, 8);
  if (AP2 <> nil) then
  begin
    TPack.UInt64_To_BE(UInt64(System.Length(AP2)) * UInt64(8), Result, 0);
  end;
end;

function TIesEngine.SimilarMacCompute(const AArgOne, AArgTwo: TCryptoLibByteArray)
  : TCryptoLibByteArray;
begin
  if (AArgOne <> nil) then
  begin
    FMac.BlockUpdate(AArgOne, 0, System.Length(AArgOne));
  end;
  if (System.Length(FV) <> 0) then
  begin
    FMac.BlockUpdate(AArgTwo, 0, System.Length(AArgTwo));
  end;
  Result := FMac.DoFinal;
end;

procedure TIesEngine.SetupBlockCipherAndMacKeyBytes(out AK1,
  AK2: TCryptoLibByteArray);
var
  LK: TCryptoLibByteArray;
  LWithCipher: IIesWithCipherParameters;
begin
  if not Supports(FParam, IIesWithCipherParameters, LWithCipher) then
    raise EArgumentCryptoLibException.CreateRes(@SIesParametersMustSupportIIesWithCipherParameters);
  System.SetLength(AK1, LWithCipher.CipherKeySize div 8);
  System.SetLength(AK2, FParam.MacKeySize div 8);
  System.SetLength(LK, System.Length(AK1) + System.Length(AK2));

  FKdf.GenerateBytes(LK, 0, System.Length(LK));

  System.Move(LK[0], AK1[0], System.Length(AK1) * System.SizeOf(Byte));
  System.Move(LK[System.Length(AK1)], AK2[0], System.Length(AK2) *
    System.SizeOf(Byte));
end;

constructor TIesEngine.Create(const AAgree: IBasicAgreement;
  const AKdf: IDerivationFunction; const AMac: IMac);
begin
  Inherited Create();
  FAgree := AAgree;
  FKdf := AKdf;
  FMac := AMac;
  FCipher := nil;
end;

constructor TIesEngine.Create(const AAgree: IBasicAgreement;
  const AKdf: IDerivationFunction; const AMac: IMac;
  const ACipher: IBufferedBlockCipher);
begin
  Inherited Create();
  FAgree := AAgree;
  FKdf := AKdf;
  FMac := AMac;
  FCipher := ACipher;
end;

function TIesEngine.DecryptBlock(const AInEnc: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LM, LK, LK1, LK2, LP2, LL2, LT1, LT2: TCryptoLibByteArray;
  LLen, LMacSize: Int32;
  LCp: ICipherParameters;
begin
  LLen := 0;
  LMacSize := FMac.GetMacSize();
  // Ensure that the length of the input is greater than the MAC in bytes
  if (AInLen < (System.Length(FV) + LMacSize)) then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes
      (@SInvalidCipherTextLength);
  end;
  // note order is important: set up keys, do simple encryptions, check mac, do final encryption.
  if (FCipher = nil) then
  begin
    // Streaming mode.
    System.SetLength(LK1, AInLen - System.Length(FV) - LMacSize);
    System.SetLength(LK2, FParam.MacKeySize div 8);
    System.SetLength(LK, System.Length(LK1) + System.Length(LK2));

    FKdf.GenerateBytes(LK, 0, System.Length(LK));

    // K2 (MAC key) from a fixed prefix, K1 (keystream) from the remainder - see EncryptBlock.
    System.Move(LK[0], LK2[0], System.Length(LK2) * System.SizeOf(Byte));
    if LK1 <> nil then
    begin
      System.Move(LK[System.Length(LK2)], LK1[0],
        System.Length(LK1) * System.SizeOf(Byte));
    end;

    // process the message
    System.SetLength(LM, System.Length(LK1));
    TByteUtilities.&Xor(System.Length(LK1), AInEnc, AInOff + System.Length(FV),
      LK1, 0, LM, 0);
  end
  else
  begin
    // Block cipher mode.

    SetupBlockCipherAndMacKeyBytes(LK1, LK2);

    LCp := TKeyParameter.Create(LK1);

    // If iv is provided use it to initialise the cipher
    if (FIV <> nil) then
    begin
      LCp := TParametersWithIV.Create(LCp, FIV);
    end;

    FCipher.Init(False, LCp);

    System.SetLength(LM, FCipher.GetOutputSize(AInLen - System.Length(FV) -
      LMacSize));

    // do initial processing
    LLen := FCipher.ProcessBytes(AInEnc, AInOff + System.Length(FV),
      AInLen - System.Length(FV) - LMacSize, LM, 0);

  end;

  // Convert the length of the encoding vector into a byte array.
  LP2 := FParam.GetEncodingV();
  LL2 := nil;
  if (System.Length(FV) <> 0) then
  begin
    LL2 := GetLengthTag(LP2);
  end;

  // Verify the MAC.
  LT1 := TArrayUtilities.CopyOfRange<Byte>(AInEnc, AInOff + AInLen - LMacSize,
    AInOff + AInLen);
  System.SetLength(LT2, System.Length(LT1));

  FMac.Init((TKeyParameter.Create(LK2) as IKeyParameter) as ICipherParameters);

  FMac.BlockUpdate(AInEnc, AInOff + System.Length(FV), AInLen - System.Length(FV)
    - LMacSize);

  LT2 := SimilarMacCompute(LP2, LL2);

  if not TArrayUtilities.FixedTimeEquals(LT1, LT2) then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SInvalidMAC);
  end;

  if (FCipher = nil) then
  begin
    Result := LM;
    Exit;
  end
  else
  begin
    // MAC must be verified above before this DoFinal: it removes padding (e.g. PKCS7), and a
    // padding failure here is distinguishable from a MAC failure, which would be a CBC padding oracle.
    // Only authenticated ciphertext reaches this point.
    LLen := LLen + FCipher.DoFinal(LM, LLen);

    Result := TArrayUtilities.CopyOfRange<Byte>(LM, 0, LLen);
    Exit;
  end;
end;

function TIesEngine.EncryptBlock(const AIn: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LC, LK, LK1, LK2, LP2, LL2, LT: TCryptoLibByteArray;
  LLen, LLenCount: Int32;
begin
  if (FCipher = nil) then
  begin
    // Streaming mode.
    System.SetLength(LK1, AInLen);
    System.SetLength(LK2, FParam.MacKeySize div 8);
    System.SetLength(LK, System.Length(LK1) + System.Length(LK2));

    FKdf.GenerateBytes(LK, 0, System.Length(LK));

    // Derive the MAC key K2 from a fixed prefix of the KDF output and the keystream K1 from
    // the remainder, regardless of whether an ephemeral V is present. Placing K1 first (the
    // legacy static-key, V-absent layout) put K2 at a message-length-dependent offset behind
    // the keystream, so a single known-plaintext leak of K1 also exposed the MAC key of any
    // shorter message - a cross-message forgery in the deterministic static-key mode. A fixed
    // K2 offset is never covered by the keystream, closing that.
    System.Move(LK[0], LK2[0], System.Length(LK2) * System.SizeOf(Byte));
    if LK1 <> nil then
    begin
      System.Move(LK[System.Length(LK2)], LK1[0],
        System.Length(LK1) * System.SizeOf(Byte));
    end;

    System.SetLength(LC, AInLen);
    TByteUtilities.&Xor(AInLen, AIn, AInOff, LK1, 0, LC, 0);
    LLen := AInLen;
  end
  else
  begin
    // Block cipher mode.

    SetupBlockCipherAndMacKeyBytes(LK1, LK2);

    // If iv is provided use it to initialise the cipher
    if (FIV <> nil) then
    begin
      FCipher.Init(True, TParametersWithIV.Create(TKeyParameter.Create(LK1)
        as IKeyParameter, FIV) as IParametersWithIV);
    end
    else
    begin
      FCipher.Init(True, TKeyParameter.Create(LK1) as IKeyParameter);
    end;

    System.SetLength(LC, FCipher.GetOutputSize(AInLen));

    LLen := FCipher.ProcessBytes(AIn, AInOff, AInLen, LC, 0);
    LLen := LLen + FCipher.DoFinal(LC, LLen);
  end;

  // Convert the length of the encoding vector into a byte array.
  LP2 := FParam.GetEncodingV();
  LL2 := nil;
  if (System.Length(FV) <> 0) then
  begin
    LL2 := GetLengthTag(LP2);
  end;

  // Apply the MAC.
  System.SetLength(LT, FMac.GetMacSize);

  FMac.Init((TKeyParameter.Create(LK2) as IKeyParameter) as ICipherParameters);
  FMac.BlockUpdate(LC, 0, System.Length(LC));

  LT := SimilarMacCompute(LP2, LL2);

  // Output the triple (V,C,T).
  // V := Ephermeral Public Key
  // C := Encrypted Payload
  // T := Authentication Message (MAC)
  System.SetLength(Result, System.Length(FV) + LLen + System.Length(LT));
  if FV <> nil then
  begin
    System.Move(FV[0], Result[0], System.Length(FV) * System.SizeOf(Byte));
  end;
  LLenCount := LLen * System.SizeOf(Byte);
  if LLenCount > 0 then
  begin
    System.Move(LC[0], Result[System.Length(FV)], LLenCount);
  end;
  System.Move(LT[0], Result[System.Length(FV) + LLen],
    System.Length(LT) * System.SizeOf(Byte));

end;

procedure TIesEngine.ExtractParams(const AParams: ICipherParameters);
var
  LParamsWithIV: IParametersWithIV;
  LIesParams: IIesParameters;
begin
  if Supports(AParams, IParametersWithIV, LParamsWithIV) then
  begin
    FIV := LParamsWithIV.GetIV;
    if not Supports(LParamsWithIV.Parameters, IIesParameters, LIesParams) then
      raise EArgumentCryptoLibException.CreateRes(@SParametersMustSupportIesParameters);
    FParam := LIesParams;
  end
  else
  begin
    FIV := nil;
    if not Supports(AParams, IIesParameters, LIesParams) then
      raise EArgumentCryptoLibException.CreateRes(@SParametersMustSupportIesParameters);
    FParam := LIesParams;
  end;
end;

function TIesEngine.GetCipher: IBufferedBlockCipher;
begin
  Result := FCipher;
end;

function TIesEngine.GetMac: IMac;
begin
  Result := FMac;
end;

procedure TIesEngine.Init(const APrivateKey: IAsymmetricKeyParameter;
  const AParams: ICipherParameters; const APublicKeyParser: IKeyParser);
begin
  FForEncryption := False;
  FPrivParam := APrivateKey;
  FKeyParser := APublicKeyParser;
  ExtractParams(AParams);
end;

procedure TIesEngine.Init(const APublicKey: IAsymmetricKeyParameter;
  const AParams: ICipherParameters;
  const AEphemeralKeyPairGenerator: IEphemeralKeyPairGenerator);
begin
  FForEncryption := True;
  FPubParam := APublicKey;
  FKeyPairGenerator := AEphemeralKeyPairGenerator;
  ExtractParams(AParams);
end;

procedure TIesEngine.Init(AForEncryption: Boolean;
  const APrivParam, APubParam, AParams: ICipherParameters);
begin
  FForEncryption := AForEncryption;
  FPrivParam := APrivParam;
  FPubParam := APubParam;
  FV := nil;
  ExtractParams(AParams);
end;

function TIesEngine.ProcessBlock(const AIn: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LEphKeyPair: IEphemeralKeyPair;
  LBIn: TBytesStream;
  LEncLength: Int32;
  LZ: TBigInteger;
  BigZ, VZ: TCryptoLibByteArray;
  LKdfParam: IKDFParameters;
begin
  if (FForEncryption) then
  begin
    if (FKeyPairGenerator <> nil) then
    begin
      LEphKeyPair := FKeyPairGenerator.Generate;

      FPrivParam := LEphKeyPair.GetKeyPair.Private;
      FV := LEphKeyPair.GetEncodedPublicKey;
    end
  end
  else
  begin
    if (FKeyParser <> nil) then
    begin
      LBIn := TBytesStream.Create(System.Copy(AIn, AInOff, AInLen));

      try
        LBIn.Position := 0;

        try
          FPubParam := FKeyParser.ReadKey(LBIn);
        except
          on e: EIOCryptoLibException do
          begin
            raise EInvalidCipherTextCryptoLibException.CreateResFmt
              (@SErrorRecoveringEphemeralPublicKey, [e.Message]);
          end;

          on e: EArgumentCryptoLibException do
          begin
            raise EInvalidCipherTextCryptoLibException.CreateResFmt
              (@SErrorRecoveringEphemeralPublicKey, [e.Message]);
          end;

        end;

        LEncLength := (AInLen - (LBIn.Size - LBIn.Position));
        FV := TArrayUtilities.CopyOfRange<Byte>(AIn, AInOff, AInOff + LEncLength);

      finally
        LBIn.Free;
      end;
    end;
  end;

  // Compute the common value and convert to byte array.
  FAgree.Init(FPrivParam);
  LZ := FAgree.CalculateAgreement(FPubParam);
  BigZ := TBigIntegerUtilities.AsUnsignedByteArray(FAgree.GetFieldSize, LZ);

  // Create input to KDF.
  if (System.Length(FV) <> 0) then
  begin
    VZ := TArrayUtilities.Concatenate<Byte>([FV, BigZ]);
    TArrayUtilities.Fill(BigZ, 0, System.Length(BigZ), Byte(0));
    BigZ := VZ;
  end;

  try
    // Initialise the KDF.
    LKdfParam := TKDFParameters.Create(BigZ, FParam.GetDerivationV);
    FKdf.Init(LKdfParam);

    if FForEncryption then
    begin
      Result := EncryptBlock(AIn, AInOff, AInLen);
      Exit;
    end
    else
    begin
      Result := DecryptBlock(AIn, AInOff, AInLen);
      Exit;
    end;

  finally
    TArrayUtilities.Fill(BigZ, 0, System.Length(BigZ), Byte(0));
  end;
end;

end.
