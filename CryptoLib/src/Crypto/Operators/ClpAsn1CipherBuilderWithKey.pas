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

unit ClpAsn1CipherBuilderWithKey;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  Rtti,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpICipher,
  ClpICipherBuilder,
  ClpICipherBuilderWithKey,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpIBufferedCipher,
  ClpIStreamCipher,
  ClpIBufferedStreamCipher,
  ClpBufferedStreamCipher,
  ClpCipherStream,
  ClpCipherFactory,
  ClpICipherKeyGenerator,
  ClpCipherKeyGeneratorFactory,
  ClpAlgorithmIdentifierFactory,
  ClpCryptoServicesRegistrar,
  ClpISecureRandom,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A cipher builder based on ASN.1 algorithm identifiers that also carries the encryption key.
  /// </summary>
  TAsn1CipherBuilderWithKey = class(TInterfacedObject, ICipherBuilderWithKey, ICipherBuilder)
  strict private
    FEncKey: IKeyParameter;
    FAlgorithmIdentifier: IAlgorithmIdentifier;

    function GetAlgorithmDetails: IAlgorithmIdentifier;
    function GetKey: ICipherParameters;

  public
    constructor Create(const AEncryptionOID: IDerObjectIdentifier; AKeySize: Int32;
      const ARandom: ISecureRandom);

    function GetMaxOutputSize(AInputLen: Int32): Int32;
    function BuildCipher(const AStream: TStream): ICipher;

    property AlgorithmDetails: IAlgorithmIdentifier read GetAlgorithmDetails;
    property Key: ICipherParameters read GetKey;
  end;

type
  /// <summary>
  /// Wrapper that adapts an IBufferedCipher into an ICipher using CipherStream.
  /// </summary>
  TBufferedCipherWrapper = class(TInterfacedObject, ICipher)
  strict private
    FBufferedCipher: IBufferedCipher;
    FStream: TCipherStream;

    function GetStream: TStream;

  public
    constructor Create(const ABufferedCipher: IBufferedCipher; const ASource: TStream;
      ALeaveOpen: Boolean);
    destructor Destroy; override;

    function GetMaxOutputSize(AInputLen: Int32): Int32;
    function GetUpdateOutputSize(AInputLen: Int32): Int32;

    property Stream: TStream read GetStream;
  end;

implementation

{ TAsn1CipherBuilderWithKey }

constructor TAsn1CipherBuilderWithKey.Create(const AEncryptionOID: IDerObjectIdentifier;
  AKeySize: Int32; const ARandom: ISecureRandom);
var
  LRandom: ISecureRandom;
  LKeyGen: ICipherKeyGenerator;
begin
  inherited Create();

  LRandom := TCryptoServicesRegistrar.GetSecureRandom(ARandom);

  LKeyGen := TCipherKeyGeneratorFactory.CreateKeyGenerator(AEncryptionOID, LRandom);

  FEncKey := LKeyGen.GenerateKeyParameter();
  FAlgorithmIdentifier := TAlgorithmIdentifierFactory.GenerateEncryptionAlgID(
    AEncryptionOID, System.Length(FEncKey.GetKey()) * 8, LRandom);
end;

function TAsn1CipherBuilderWithKey.GetAlgorithmDetails: IAlgorithmIdentifier;
begin
  Result := FAlgorithmIdentifier;
end;

function TAsn1CipherBuilderWithKey.GetMaxOutputSize(AInputLen: Int32): Int32;
begin
  raise ENotImplementedCryptoLibException.Create('GetMaxOutputSize');
end;

function TAsn1CipherBuilderWithKey.BuildCipher(const AStream: TStream): ICipher;
var
  LCipherValue: TValue;
  LBufferedCipher: IBufferedCipher;
  LStreamCipher: IStreamCipher;
  LStream: TStream;
  LLeaveOpen: Boolean;
begin
  LCipherValue := TCipherFactory.CreateContentCipher(True, FEncKey, FAlgorithmIdentifier);

  if LCipherValue.TryAsType<IBufferedCipher>(LBufferedCipher) then
  begin
    // Already a buffered cipher, use directly
  end
  else if LCipherValue.TryAsType<IStreamCipher>(LStreamCipher) then
  begin
    LBufferedCipher := TBufferedStreamCipher.Create(LStreamCipher) as IBufferedCipher;
  end
  else
  begin
    raise EInvalidOperationCryptoLibException.Create('Unexpected cipher type');
  end;

  if AStream <> nil then
  begin
    LStream := AStream;
    LLeaveOpen := True;
  end
  else
  begin
    LStream := TMemoryStream.Create();
    LLeaveOpen := False;
  end;

  Result := TBufferedCipherWrapper.Create(LBufferedCipher, LStream, LLeaveOpen);
end;

function TAsn1CipherBuilderWithKey.GetKey: ICipherParameters;
begin
  Result := FEncKey;
end;

{ TBufferedCipherWrapper }

constructor TBufferedCipherWrapper.Create(const ABufferedCipher: IBufferedCipher;
  const ASource: TStream; ALeaveOpen: Boolean);
begin
  inherited Create();
  FBufferedCipher := ABufferedCipher;
  FStream := TCipherStream.Create(ASource, ABufferedCipher, ABufferedCipher, ALeaveOpen);
end;

destructor TBufferedCipherWrapper.Destroy;
begin
  FStream.Free;
  inherited Destroy;
end;

function TBufferedCipherWrapper.GetMaxOutputSize(AInputLen: Int32): Int32;
begin
  Result := FBufferedCipher.GetOutputSize(AInputLen);
end;

function TBufferedCipherWrapper.GetUpdateOutputSize(AInputLen: Int32): Int32;
begin
  Result := FBufferedCipher.GetUpdateOutputSize(AInputLen);
end;

function TBufferedCipherWrapper.GetStream: TStream;
begin
  Result := FStream;
end;

end.
