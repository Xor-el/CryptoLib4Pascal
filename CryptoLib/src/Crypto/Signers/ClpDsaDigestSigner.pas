unit ClpDsaDigestSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses

  SysUtils,
  HlpIHash,
  ClpIDsa,
  ClpIAsn1Sequence,
  ClpIDerInteger,
  ClpDerSequence,
  ClpDerInteger,
  ClpBigInteger,
  ClpAsn1Object,
  ClpCryptoLibTypes,
  ClpIParametersWithRandom,
  ClpIAsymmetricKeyParameter,
  ClpICipherParameters,
  ClpISigner,
  ClpIDsaDigestSigner;

resourcestring
  SPrivateKey = 'Signing Requires Private Key.';
  SPublicKey = 'Verification Requires Public Key.';
  SDSaDigestSignerNotInitializedForSignatureGeneration =
    'DSADigestSigner not Initialized for Signature Generation.';
  SDSaDigestSignerNotInitializedForVerification =
    'DSADigestSigner not Initialized for Verification';

type
  TDsaDigestSigner = class(TInterfacedObject, ISigner, IDsaDigestSigner)

  strict private
  var
    Fdigest: IHash;
    FdsaSigner: IDsa;
    FforSigning: Boolean;

    function DerEncode(const r, s: TBigInteger): TCryptoLibByteArray; inline;

    function DerDecode(encoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>; inline;

  public
    constructor Create(const signer: IDsa; const digest: IHash);

    function GetAlgorithmName: String; virtual;
    property AlgorithmName: String read GetAlgorithmName;

    procedure Init(forSigning: Boolean;
      const parameters: ICipherParameters); virtual;

    /// <summary>
    /// update the internal digest with the byte b
    /// </summary>
    procedure Update(input: Byte); virtual;

    /// <summary>
    /// update the internal digest with the byte array in
    /// </summary>
    procedure BlockUpdate(input: TCryptoLibByteArray;
      inOff, length: Int32); virtual;

    /// <summary>
    /// Generate a signature for the message we've been loaded with using the
    /// key we were initialised with.
    /// </summary>
    function GenerateSignature(): TCryptoLibByteArray; virtual;

    /// <returns>
    /// true if the internal state represents the signature described in the
    /// passed in array.
    /// </returns>
    function VerifySignature(signature: TCryptoLibByteArray): Boolean; virtual;

    /// <summary>
    /// Reset the internal state
    /// </summary>
    procedure Reset(); virtual;

  end;

implementation

{ TDsaDigestSigner }

procedure TDsaDigestSigner.BlockUpdate(input: TCryptoLibByteArray;
  inOff, length: Int32);
begin
  Fdigest.TransformBytes(input, inOff, length);
end;

constructor TDsaDigestSigner.Create(const signer: IDsa; const digest: IHash);
begin
  FdsaSigner := signer;
  Fdigest := digest;
end;

function TDsaDigestSigner.DerDecode(encoding: TCryptoLibByteArray)
  : TCryptoLibGenericArray<TBigInteger>;
var
  s: IAsn1Sequence;
begin
  s := TAsn1Object.FromByteArray(encoding) as IAsn1Sequence;
  Result := TCryptoLibGenericArray<TBigInteger>.Create
    ((s[0] as IDerInteger).Value, (s[1] as IDerInteger).Value);
end;

function TDsaDigestSigner.DerEncode(const r, s: TBigInteger)
  : TCryptoLibByteArray;
begin
  Result := TDerSequence.Create([TDerInteger.Create(r) as IDerInteger,
    TDerInteger.Create(s) as IDerInteger]).GetDerEncoded();
end;

function TDsaDigestSigner.GenerateSignature: TCryptoLibByteArray;
var
  hash: TCryptoLibByteArray;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  if ((not FforSigning)) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SDSaDigestSignerNotInitializedForSignatureGeneration);
  end;

  System.SetLength(hash, Fdigest.HashSize);

  hash := Fdigest.TransformFinal().GetBytes;

  sig := FdsaSigner.GenerateSignature(hash);

  Result := DerEncode(sig[0], sig[1]);
end;

function TDsaDigestSigner.GetAlgorithmName: String;
begin
  Result := Fdigest.Name + 'with' + FdsaSigner.AlgorithmName;
end;

procedure TDsaDigestSigner.Init(forSigning: Boolean;
  const parameters: ICipherParameters);
var
  k: IAsymmetricKeyParameter;
  withRandom: IParametersWithRandom;
begin
  FforSigning := forSigning;

  if (Supports(parameters, IParametersWithRandom, withRandom)) then
  begin
    k := withRandom.parameters as IAsymmetricKeyParameter;
  end
  else
  begin
    k := parameters as IAsymmetricKeyParameter;
  end;

  if ((forSigning) and (not k.IsPrivate)) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SPrivateKey);
  end;

  if ((not forSigning) and (k.IsPrivate)) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SPublicKey);
  end;

  Reset();

  FdsaSigner.Init(forSigning, parameters);
end;

procedure TDsaDigestSigner.Reset;
begin
  Fdigest.Initialize;
end;

procedure TDsaDigestSigner.Update(input: Byte);
begin
  Fdigest.TransformUntyped(input, System.SizeOf(Byte));
end;

function TDsaDigestSigner.VerifySignature
  (signature: TCryptoLibByteArray): Boolean;
var
  hash: TCryptoLibByteArray;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  if (FforSigning) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SDSaDigestSignerNotInitializedForVerification);
  end;

  System.SetLength(hash, Fdigest.HashSize);

  hash := Fdigest.TransformFinal().GetBytes;

  try

    sig := DerDecode(signature);
    Result := FdsaSigner.VerifySignature(hash, sig[0], sig[1]);

  except
    on e: EIOCryptoLibException do
    begin
      Result := false;
    end;

  end;

end;

end.
