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

unit ClpPascalCoinIesEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  ClpIMac,
  ClpIPascalCoinIESEngine,
  ClpICipherParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIKeyParser,
  ClpIEphemeralKeyPair,
  ClpKdfParameters,
  ClpIKdfParameters,
  ClpIESEngine,
  ClpArrayUtilities,
  ClpBigInteger,
  ClpBigIntegers,
  ClpCryptoLibTypes;

resourcestring
  SErrorRecoveringEphemeralPublicKey =
    'Unable to Recover Ephemeral Public Key: "%s"';
  SInvalidCipherTextLength =
    'Length of Input Must be Greater than the MAC and V Combined';
  SInvalidMAC = 'Invalid MAC';
  SCipherCannotbeNilInThisMode = 'Cipher Cannot be Nil in This Mode.';

type

  /// <summary>
  /// Compatibility Class for PascalCoin IESEngine
  /// </summary>
  TPascalCoinIesEngine = class(TIesEngine, IPascalCoinIesEngine)

  strict private
  type
    /// <summary>
    /// Structure for Compatibility with PascalCoin Original
    /// Implementation.
    /// </summary>
    TSecureHead = record
      Key: Byte;
      Mac: Byte;
      Orig: UInt16;
      Body: UInt16;
    end;

  const
    /// <summary>
    /// <b>SizeOf <paramref name="TSecureHead" /></b>. <br />
    /// </summary>
    // SECURE_HEAD_SIZE = Int32(6);
    SECURE_HEAD_SIZE = System.SizeOf(TSecureHead);

  strict protected

    function EncryptBlock(const AIn: TCryptoLibByteArray; AInOff, AInLen: Int32)
      : TCryptoLibByteArray; override;

    function DecryptBlock(const AInEnc: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray; override;

  public

    function ProcessBlock(const AIn: TCryptoLibByteArray; AInOff, AInLen: Int32)
      : TCryptoLibByteArray; override;

  end;

implementation

{ TPascalCoinIESEngine }

function TPascalCoinIesEngine.DecryptBlock(const AInEnc: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LK1, LK2, LT1, LT2: TCryptoLibByteArray;
  LCp: ICipherParameters;
begin
  // Ensure that the length of the input is greater than the MAC in bytes
  if (AInLen < (System.Length(FV) + FMac.GetMacSize)) then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes
      (@SInvalidCipherTextLength);
  end;
  // note order is important: set up keys, do simple encryptions, check mac, do final encryption.
  if (FCipher = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes
      (@SCipherCannotbeNilInThisMode);
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

  end;

  // Verify the MAC.
  LT1 := System.Copy(AInEnc, System.Length(FV), FMac.GetMacSize);
  System.SetLength(LT2, System.Length(LT1));

  FMac.Init((TKeyParameter.Create(LK2) as IKeyParameter) as ICipherParameters);

  FMac.BlockUpdate(AInEnc, AInOff + System.Length(FV) + System.Length(LT2),
    AInLen - System.Length(FV) - System.Length(LT2));

  LT2 := FMac.DoFinal();

  if not TArrayUtilities.FixedTimeEquals(LT1, LT2) then
  begin
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SInvalidMAC);
  end;

  Result := FCipher.DoFinal(AInEnc, AInOff + System.Length(FV) + FMac.GetMacSize,
    AInLen - System.Length(FV) - System.Length(LT2));
  Exit;
end;

function TPascalCoinIesEngine.EncryptBlock(const AIn: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LC, LK1, LK2, LT: TCryptoLibByteArray;
  LMessageToEncryptPadSize, LCipherBlockSize, LMessageToEncryptSize: Int32;
begin
  if (FCipher = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes
      (@SCipherCannotbeNilInThisMode);
  end
  else
  begin
    // Block cipher mode.

    SetupBlockCipherAndMacKeyBytes(LK1, LK2);

    // If iv is provided use it to initialise the cipher
    if (FIV <> nil) then
    begin
      FCipher.Init(True, TParametersWithIV.Create(TKeyParameter.Create(LK1)
        as IKeyParameter, FIV));
    end
    else
    begin
      FCipher.Init(True, TKeyParameter.Create(LK1) as IKeyParameter);
    end;

    LC := FCipher.DoFinal(AIn, AInOff, AInLen);
  end;

  // Apply the MAC.
  System.SetLength(LT, FMac.GetMacSize);

  FMac.Init((TKeyParameter.Create(LK2) as IKeyParameter) as ICipherParameters);

  FMac.BlockUpdate(LC, 0, System.Length(LC));

  LT := FMac.DoFinal();
  LCipherBlockSize := FCipher.GetBlockSize;
  LMessageToEncryptSize := AInLen - AInOff;

  if (LMessageToEncryptSize mod LCipherBlockSize) = 0 then
  begin
    LMessageToEncryptPadSize := 0
  end
  else
  begin
    LMessageToEncryptPadSize := LCipherBlockSize -
      (LMessageToEncryptSize mod LCipherBlockSize);
  end;
  // Output the quadruple (SECURE_HEAD_DETAILS,V,T,C).
  // SECURE_HEAD_DETAILS :=
  // [0] := Convert Byte(Length(V)) to a ByteArray,
  // [1] := Convert Byte(Length(T)) to a ByteArray,
  // [2] and [3] := Convert UInt16(MessageToEncryptSize) to a ByteArray,
  // [4] and [5] := Convert UInt16(MessageToEncryptSize + MessageToEncryptPadSize) to a ByteArray,
  // V := Ephemeral Public Key
  // T := Authentication Message (MAC)
  // C := Encrypted Payload

  System.SetLength(Result, SECURE_HEAD_SIZE + System.Length(FV) +
    System.Length(LT) + System.Length(LC));

  PByte(Result)^ := Byte(System.Length(FV));
  (PByte(Result) + 1)^ := Byte(System.Length(LT));
  (PWord(Result) + 1)^ := UInt16(LMessageToEncryptSize);
  (PWord(Result) + 2)^ :=
    UInt16(LMessageToEncryptSize + LMessageToEncryptPadSize);

  System.Move(FV[0], Result[SECURE_HEAD_SIZE], System.Length(FV) *
    System.SizeOf(Byte));

  System.Move(LT[0], Result[SECURE_HEAD_SIZE + System.Length(FV)],
    System.Length(LT) * System.SizeOf(Byte));

  System.Move(LC[0], Result[SECURE_HEAD_SIZE + System.Length(FV) +
    System.Length(LT)], System.Length(LC) * System.SizeOf(Byte));

end;

function TPascalCoinIesEngine.ProcessBlock(const AIn: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LEphKeyPair: IEphemeralKeyPair;
  LBIn: TBytesStream;
  LEncLength: Int32;
  LZ: TBigInteger;
  LBigZ: TCryptoLibByteArray;
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
      // used TBytesStream here for one pass creation and population with byte array :)
      LBIn := TBytesStream.Create(System.Copy(AIn, AInOff, AInLen));

      try
        // for existing PascalCoin compatiblity purposes
        LBIn.Position := SECURE_HEAD_SIZE;

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
        FV := TArrayUtilities.CopyOfRange<Byte>(AIn, AInOff + SECURE_HEAD_SIZE,
          AInOff + LEncLength);

      finally
        LBIn.Free;
      end;
    end;
  end;

  // Compute the common value and convert to byte array.
  FAgree.Init(FPrivParam);
  LZ := FAgree.CalculateAgreement(FPubParam);
  LBigZ := TBigIntegers.AsUnsignedByteArray(FAgree.GetFieldSize, LZ);

  try
    // Initialise the KDF.
    LKdfParam := TKDFParameters.Create(LBigZ, nil);
    FKdf.Init(LKdfParam);

    if FForEncryption then
    begin
      Result := EncryptBlock(AIn, AInOff, AInLen);
      Exit;
    end
    else
    begin
      Result := DecryptBlock(System.Copy(AIn, AInOff + SECURE_HEAD_SIZE,
        AInLen - SECURE_HEAD_SIZE), AInOff, AInLen - SECURE_HEAD_SIZE);
      Exit;
    end;

  finally
    TArrayUtilities.Fill<Byte>(LBigZ, 0, System.Length(LBigZ), Byte(0));
  end;
end;

end.
