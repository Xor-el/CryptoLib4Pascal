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

unit ClpGenericSigner;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpICipherParameters,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricBlockCipher,
  ClpIDigest,
  ClpISigner,
  ClpIGenericSigner,
  ClpParameterUtilities,
  ClpDigestUtilities,
  ClpArrayUtils,
  ClpCryptoLibTypes;

resourcestring
  SSigningRequiresPrivate = 'Signing requires private key.';
  SVerificationRequiresPublic = 'Verification requires public key.';
  SNotInitForSigning = 'GenericSigner not initialised for signature generation.';
  SNotInitForVerification = 'GenericSigner not initialised for verification';

type
  /// <summary>
  /// A generic signer that uses an asymmetric block cipher and a digest.
  /// </summary>
  TGenericSigner = class(TInterfacedObject, ISigner, IGenericSigner)

  strict private
  var
    FEngine: IAsymmetricBlockCipher;
    FDigest: IDigest;
    FForSigning: Boolean;

  strict protected
    function GetAlgorithmName: String;

  public
    constructor Create(const engine: IAsymmetricBlockCipher;
      const digest: IDigest);

    procedure Init(forSigning: Boolean; const parameters: ICipherParameters);
    procedure Update(input: Byte);
    procedure BlockUpdate(const input: TCryptoLibByteArray;
      inOff, len: Int32);
    function GetMaxSignatureSize: Int32;
    function GenerateSignature: TCryptoLibByteArray;
    function VerifySignature(const signature: TCryptoLibByteArray): Boolean;
    procedure Reset;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TGenericSigner }

constructor TGenericSigner.Create(const engine: IAsymmetricBlockCipher;
  const digest: IDigest);
begin
  inherited Create();
  FEngine := engine;
  FDigest := digest;
end;

function TGenericSigner.GetAlgorithmName: String;
begin
  Result := 'Generic(' + FEngine.AlgorithmName + '/' + FDigest.AlgorithmName + ')';
end;

procedure TGenericSigner.Init(forSigning: Boolean;
  const parameters: ICipherParameters);
var
  key: IAsymmetricKeyParameter;
  keyParams: ICipherParameters;
begin
  FForSigning := forSigning;

  keyParams := TParameterUtilities.IgnoreRandom(parameters);

  if not Supports(keyParams, IAsymmetricKeyParameter, key) then
  begin
    raise EInvalidKeyCryptoLibException.Create('Expected asymmetric key parameter');
  end;

  if forSigning and (not key.IsPrivate) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SSigningRequiresPrivate);
  end;

  if (not forSigning) and key.IsPrivate then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SVerificationRequiresPublic);
  end;

  Reset();

  FEngine.Init(forSigning, parameters);
end;

procedure TGenericSigner.Update(input: Byte);
begin
  FDigest.Update(input);
end;

procedure TGenericSigner.BlockUpdate(const input: TCryptoLibByteArray;
  inOff, len: Int32);
begin
  FDigest.BlockUpdate(input, inOff, len);
end;

function TGenericSigner.GetMaxSignatureSize: Int32;
begin
  Result := FEngine.OutputBlockSize;
end;

function TGenericSigner.GenerateSignature: TCryptoLibByteArray;
var
  hash: TCryptoLibByteArray;
begin
  if not FForSigning then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitForSigning);
  end;

  hash := TDigestUtilities.DoFinal(FDigest);

  Result := FEngine.ProcessBlock(hash, 0, System.Length(hash));
end;

function TGenericSigner.VerifySignature(
  const signature: TCryptoLibByteArray): Boolean;
var
  hash, sig, tmp: TCryptoLibByteArray;
begin
  if FForSigning then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitForVerification);
  end;

  hash := TDigestUtilities.DoFinal(FDigest);

  try
    sig := FEngine.ProcessBlock(signature, 0, System.Length(signature));

    // Extend with leading zeroes to match the digest size, if necessary.
    if System.Length(sig) < System.Length(hash) then
    begin
      SetLength(tmp, System.Length(hash));
      System.Move(sig[0], tmp[System.Length(tmp) - System.Length(sig)],
        System.Length(sig));
      sig := tmp;
    end;

    Result := TArrayUtils.ConstantTimeAreEqual(sig, hash);
  except
    Result := False;
  end;
end;

procedure TGenericSigner.Reset;
begin
  FDigest.Reset();
end;

end.
