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

unit ClpIESCipher;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpIIESEngine,
  ClpIECIESPublicKeyParser,
  ClpECIESPublicKeyParser,
  ClpIAsymmetricKeyParameter,
  ClpIIESWithCipherParameters,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpIECKeyParameters,
  ClpIESWithCipherParameters,
  ClpIECDomainParameters,
  ClpIECKeyPairGenerator,
  ClpECKeyPairGenerator,
  ClpECKeyGenerationParameters,
  ClpIECKeyGenerationParameters,
  ClpEphemeralKeyPairGenerator,
  ClpIEphemeralKeyPairGenerator,
  ClpParametersWithIV,
  ClpIECPublicKeyParameters,
  ClpIIESCipher,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SInvalidPublicKey =
    'Must be Passed Recipient''s Public EC Key for Encryption';
  SInvalidPrivateKey =
    'Must be Passed Recipient''s Private EC Key for Decryption';
  SIESWithCipherParametersCannotBeNil = 'IESWithCipherParameters Cannot Be Nil';
  SUnableToProcessBlock = 'Unable to Process Block. "%s"';

type
  TIESCipher = class sealed(TInterfacedObject, IIESCipher)

  strict private
  var
    FEngine: IIESEngine;
    FForEncryption: Boolean;
    FBuffer: TMemoryStream;
    FIESWithCipherParameters: IIESWithCipherParameters;
    Fkey: IAsymmetricKeyParameter;
    FRandom: ISecureRandom;

    function Aggregate: TCryptoLibByteArray; inline;

    function KeyEncoder(const keyParameter: IAsymmetricKeyParameter;
      UsePointCompression: Boolean): TCryptoLibByteArray; inline;

  public
    procedure Init(ForEncryption: Boolean; const Key: ICipherParameters;
      const params: IIESWithCipherParameters; const Random: ISecureRandom);

    procedure ProcessBytes(input: TCryptoLibByteArray); overload;
    procedure ProcessBytes(input: TCryptoLibByteArray;
      inputOffset, inputLen: Int32); overload;

    function DoFinal(input: TCryptoLibByteArray): TCryptoLibByteArray; overload;

    function DoFinal(input: TCryptoLibByteArray; inputOffset, inputLen: Int32)
      : TCryptoLibByteArray; overload;

    function DoFinal(input: TCryptoLibByteArray; inputOffset, inputLen: Int32;
      output: TCryptoLibByteArray; outputOffset: Int32): Int32; overload;

    constructor Create(const Engine: IIESEngine);
    destructor Destroy(); override;

  end;

implementation

{ TIESCipher }

function TIESCipher.KeyEncoder(const keyParameter: IAsymmetricKeyParameter;
  UsePointCompression: Boolean): TCryptoLibByteArray;
begin
  Result := (keyParameter as IECPublicKeyParameters)
    .Q.GetEncoded(UsePointCompression);
end;

function TIESCipher.Aggregate: TCryptoLibByteArray;
begin
  FBuffer.Position := 0;
  System.SetLength(Result, FBuffer.Size);
  FBuffer.Read(Result[0], FBuffer.Size);
end;

constructor TIESCipher.Create(const Engine: IIESEngine);
begin
  Inherited Create();
  FEngine := Engine;
  FBuffer := TMemoryStream.Create();
end;

function TIESCipher.DoFinal(input: TCryptoLibByteArray;
  inputOffset, inputLen: Int32): TCryptoLibByteArray;
var
  &in: TCryptoLibByteArray;
  params: ICipherParameters;
  ecParams: IECDomainParameters;
  gen: IECKeyPairGenerator;
  kGen: IEphemeralKeyPairGenerator;
  UsePointCompression: Boolean;
begin
  if (inputLen <> 0) then
  begin
    FBuffer.Write(input[inputOffset], inputLen);
  end;

  &in := Aggregate();
  FBuffer.Clear;
  FBuffer.SetSize(0);

  // Copy parameters for use in IESEngine
  params := TIESWithCipherParameters.Create
    (FIESWithCipherParameters.GetDerivationV,
    FIESWithCipherParameters.GetEncodingV, FIESWithCipherParameters.Nonce,
    FIESWithCipherParameters.MacKeySize, FIESWithCipherParameters.CipherKeySize,
    FIESWithCipherParameters.PointCompression);

  if (FIESWithCipherParameters.Nonce <> Nil) then
  begin
    params := TParametersWithIV.Create(params, FIESWithCipherParameters.Nonce);
  end;
  ecParams := (Fkey as IECKeyParameters).Parameters;

  if FForEncryption then
  begin
    // Generate the ephemeral key pair
    gen := TECKeyPairGenerator.Create();
    gen.Init(TECKeyGenerationParameters.Create(ecParams, FRandom)
      as IECKeyGenerationParameters);

    UsePointCompression := FIESWithCipherParameters.PointCompression;

    kGen := TEphemeralKeyPairGenerator.Create(gen, UsePointCompression,
      KeyEncoder);

    // Encrypt the buffer

    try
      FEngine.Init(Fkey, params, kGen);

      Result := FEngine.ProcessBlock(&in, 0, System.length(&in));
      Exit;
    except
      on e: Exception do
      begin
        raise EBadBlockCryptoLibException.CreateResFmt(@SUnableToProcessBlock,
          [e.Message]);
      end;
    end;
  end
  else
  begin
    // Decrypt the buffer

    try
      FEngine.Init(Fkey, params, TECIESPublicKeyParser.Create(ecParams)
        as IECIESPublicKeyParser);

      Result := FEngine.ProcessBlock(&in, 0, System.length(&in));
      Exit;
    except
      on e: EInvalidCipherTextCryptoLibException do
      begin
        raise EBadBlockCryptoLibException.CreateResFmt(@SUnableToProcessBlock,
          [e.Message]);
      end;
    end;
  end;

end;

destructor TIESCipher.Destroy;
begin
  FBuffer.Free;
  inherited Destroy;
end;

function TIESCipher.DoFinal(input: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := DoFinal(input, 0, System.length(input));
end;

function TIESCipher.DoFinal(input: TCryptoLibByteArray;
  inputOffset, inputLen: Int32; output: TCryptoLibByteArray;
  outputOffset: Int32): Int32;
var
  buf: TCryptoLibByteArray;
begin
  buf := DoFinal(input, inputOffset, inputLen);
  System.Move(buf[0], output[outputOffset], System.length(buf) *
    System.SizeOf(Byte));
  Result := System.length(buf);
end;

procedure TIESCipher.Init(ForEncryption: Boolean; const Key: ICipherParameters;
  const params: IIESWithCipherParameters; const Random: ISecureRandom);
var
  LKey: ICipherParameters;
begin
  FForEncryption := ForEncryption;
  LKey := Key;
  // Parse the recipient's key
  if ForEncryption then
  begin
    if ((not Supports(LKey, IAsymmetricKeyParameter, Fkey)) or
      ((Fkey.IsPrivate))) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SInvalidPublicKey);
    end;

  end
  else
  begin
    if Supports(LKey, IParametersWithRandom) then
    begin
      LKey := (LKey as IParametersWithRandom).Parameters;
    end;

    if ((not Supports(LKey, IAsymmetricKeyParameter, Fkey)) or
      (not(Fkey.IsPrivate))) then
    begin
      raise EInvalidKeyCryptoLibException.CreateRes(@SInvalidPrivateKey);
    end;

  end;
  if params = Nil then
  begin
    raise EArgumentNilCryptoLibException.CreateRes
      (@SIESWithCipherParametersCannotBeNil);
  end
  else
  begin
    FIESWithCipherParameters := params;
  end;
  FRandom := Random;
  FBuffer.Clear;
  FBuffer.SetSize(0);
end;

procedure TIESCipher.ProcessBytes(input: TCryptoLibByteArray);
begin
  ProcessBytes(input, 0, System.length(input));
end;

procedure TIESCipher.ProcessBytes(input: TCryptoLibByteArray;
  inputOffset, inputLen: Int32);
begin
  FBuffer.Write(input[inputOffset], inputLen);
end;

end.
