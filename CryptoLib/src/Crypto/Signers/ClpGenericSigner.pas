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
  ClpArrayUtilities,
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
    constructor Create(const AEngine: IAsymmetricBlockCipher;
      const ADigest: IDigest);

    procedure Init(AForSigning: Boolean; const AParameters: ICipherParameters);
    procedure Update(AInput: Byte);
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32);
    function GetMaxSignatureSize: Int32;
    function GenerateSignature: TCryptoLibByteArray;
    function VerifySignature(const ASignature: TCryptoLibByteArray): Boolean;
    procedure Reset;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TGenericSigner }

constructor TGenericSigner.Create(const AEngine: IAsymmetricBlockCipher;
  const ADigest: IDigest);
begin
  inherited Create();
  FEngine := AEngine;
  FDigest := ADigest;
end;

function TGenericSigner.GetAlgorithmName: String;
begin
  Result := 'Generic(' + FEngine.AlgorithmName + '/' + FDigest.AlgorithmName + ')';
end;

procedure TGenericSigner.Init(AForSigning: Boolean;
  const AParameters: ICipherParameters);
var
  LKey: IAsymmetricKeyParameter;
  LKeyParams: ICipherParameters;
begin
  FForSigning := AForSigning;

  LKeyParams := TParameterUtilities.IgnoreRandom(AParameters);

  if not Supports(LKeyParams, IAsymmetricKeyParameter, LKey) then
  begin
    raise EInvalidKeyCryptoLibException.Create('Expected asymmetric key parameter');
  end;

  if AForSigning and (not LKey.IsPrivate) then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SSigningRequiresPrivate);
  end;

  if (not AForSigning) and LKey.IsPrivate then
  begin
    raise EInvalidKeyCryptoLibException.CreateRes(@SVerificationRequiresPublic);
  end;

  Reset();

  FEngine.Init(AForSigning, AParameters);
end;

procedure TGenericSigner.Update(AInput: Byte);
begin
  FDigest.Update(AInput);
end;

procedure TGenericSigner.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32);
begin
  FDigest.BlockUpdate(AInput, AInOff, ALength);
end;

function TGenericSigner.GetMaxSignatureSize: Int32;
begin
  Result := FEngine.OutputBlockSize;
end;

function TGenericSigner.GenerateSignature: TCryptoLibByteArray;
var
  LHash: TCryptoLibByteArray;
begin
  if not FForSigning then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitForSigning);
  end;

  LHash := TDigestUtilities.DoFinal(FDigest);

  Result := FEngine.ProcessBlock(LHash, 0, System.Length(LHash));
end;

function TGenericSigner.VerifySignature(
  const ASignature: TCryptoLibByteArray): Boolean;
var
  LHash, LSig, LTmp: TCryptoLibByteArray;
begin
  if FForSigning then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitForVerification);
  end;

  LHash := TDigestUtilities.DoFinal(FDigest);

  try
    LSig := FEngine.ProcessBlock(ASignature, 0, System.Length(ASignature));

    // Extend with leading zeroes to match the digest size, if necessary.
    if System.Length(LSig) < System.Length(LHash) then
    begin
      SetLength(LTmp, System.Length(LHash));
      System.Move(LSig[0], LTmp[System.Length(LTmp) - System.Length(LSig)],
        System.Length(LSig));
      LSig := LTmp;
    end;

    Result := TArrayUtilities.FixedTimeEquals(LSig, LHash);
  except
    Result := False;
  end;
end;

procedure TGenericSigner.Reset;
begin
  FDigest.Reset();
end;

end.
