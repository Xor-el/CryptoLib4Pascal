{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit UsageExamples;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIX9ECParameters,
  ClpIECDomainParameters,
  ClpECDomainParameters,
  ClpIECKeyPairGenerator,
  ClpECKeyPairGenerator,
  ClpIECKeyGenerationParameters,
  ClpECKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpECPublicKeyParameters,
  ClpECPrivateKeyParameters,
  ClpIECInterface,
  ClpECPoint,
  ClpISigner,
  ClpSignerUtilities,
  ClpSecNamedCurves;

type
  TUsageExamples = class sealed(TObject)

  strict private

  const

    /// <summary>
    /// supported curves are secp256k1, sect283k1, secp384r1 and secp521r1
    /// </summary>
    CurveName = 'secp256k1';

    /// <summary>
    /// supported signing algorithms are NONEwithECDSA, SHA-1withECDSA, <br />
    /// SHA-224withECDSA, SHA-256withECDSA, SHA-384withECDSA,
    /// SHA-512withECDSA and RIPEMD160withECDSA
    /// </summary>
    SigningAlgorithm = 'SHA-1withECDSA';

  class var
    FRandom: ISecureRandom;
    FCurve: IX9ECParameters;
    class function BytesToHexString(input: TBytes): String; static;
    class constructor UsageExamples();

  public
    class procedure GenerateKeyPairAndSign(); static;
    class procedure GetPublicKeyFromPrivateKey(); static;
    class procedure RecreatePublicAndPrivateKeyPairsFromByteArray(); static;
    class procedure RecreatePublicKeyFromXAndYCoordByteArray(); static;
  end;

implementation

{ TUsageExamples }

class function TUsageExamples.BytesToHexString(input: TBytes): String;
var
  index: Int32;
begin
  Result := '';
  for index := System.Low(input) to System.High(input) do
  begin
    if index = 0 then
    begin
      Result := Result + IntToHex(input[index], 2);
    end
    else
    begin
      Result := Result + ',' + IntToHex(input[index], 2);
    end;
  end;
  Result := '[' + Result + ']';
end;

class procedure TUsageExamples.GenerateKeyPairAndSign;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams: IECPublicKeyParameters;
  signer: ISigner;
  &message, sigBytes: TBytes;
const
  MethodName = 'GenerateKeyPairAndSign';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  Writeln('Public Key Normalized XCoord is: ' +
    pubParams.Q.Normalize.AffineXCoord.ToBigInteger.ToString(16) + sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' +
    pubParams.Q.Normalize.AffineYCoord.ToBigInteger.ToString(16) + sLineBreak);

  Writeln('Private Key D Parameter is: ' + privParams.D.ToString(16) +
    sLineBreak);

  signer := TSignerUtilities.GetSigner(SigningAlgorithm);

  Writeln('Signer Name is: ' + signer.AlgorithmName + sLineBreak);

  // sign

  signer.Init(true, privParams);

  &message := TEncoding.UTF8.GetBytes('PascalECDSA');

  signer.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := signer.GenerateSignature();

  Writeln('Generated Signature is: ' + BytesToHexString(sigBytes) + sLineBreak);

  // verify

  signer.Init(false, pubParams);

  signer.BlockUpdate(&message, 0, System.Length(&message));

  if (not signer.VerifySignature(sigBytes)) then
  begin
    Writeln(pubParams.AlgorithmName + ' verification failed' + sLineBreak);
  end
  else
  begin
    Writeln(pubParams.AlgorithmName + ' verification passed' + sLineBreak);
  end;

end;

class procedure TUsageExamples.GetPublicKeyFromPrivateKey;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  privParams: IECPrivateKeyParameters;
  pubParams, recreatedPubKeyParameters: IECPublicKeyParameters;
  EncodedPublicKey, RecreatedEncodedPublicKey: TBytes;
  qPoint: IECPoint;
const
  MethodName = 'GetPublicKeyFromPrivateKey';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  Writeln('Public Key Normalized XCoord is: ' +
    pubParams.Q.Normalize.AffineXCoord.ToBigInteger.ToString(16) + sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' +
    pubParams.Q.Normalize.AffineYCoord.ToBigInteger.ToString(16) + sLineBreak);

  EncodedPublicKey := pubParams.Q.Normalize.GetEncoded;

  Writeln('Encoded Public Key is: ' + BytesToHexString(EncodedPublicKey) +
    sLineBreak);

  Writeln('Private Key D Parameter is: ' + privParams.D.ToString(16) +
    sLineBreak);

  // get public key from private key

  // Method One

  qPoint := domain.G.Multiply(privParams.D);

  RecreatedEncodedPublicKey := qPoint.GetEncoded();

  if CompareMem(PByte(EncodedPublicKey), PByte(RecreatedEncodedPublicKey),
    System.Length(EncodedPublicKey) * System.SizeOf(Byte)) then
  begin
    Writeln('Public Key Recreation From Private Key Was Successful' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation From Private Key Failed' + sLineBreak);
  end;

  recreatedPubKeyParameters := TECPublicKeyParameters.Create(qPoint, domain);

  if pubParams.Equals(recreatedPubKeyParameters) then
  begin
    Writeln('Public Key Recreation Match With Original Public Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation DOES NOT Match With Original Public Key' +
      sLineBreak);
  end;

  // or the easier method
  // Method Two (** Preferred **)

  if pubParams.Equals(TECKeyPairGenerator.GetCorrespondingPublicKey(privParams))
  then
  begin
    Writeln('Public Key Recreation Match With Original Public Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation DOES NOT Match With Original Public Key' +
      sLineBreak);
  end;

end;

class procedure TUsageExamples.RecreatePublicAndPrivateKeyPairsFromByteArray;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  privParams, RegeneratedPrivateKey: IECPrivateKeyParameters;
  pubParams, RegeneratedPublicKey: IECPublicKeyParameters;
  PublicKeyByteArray, PrivateKeyByteArray: TBytes;
  PrivD: TBigInteger;
const
  MethodName = 'RecreatePublicAndPrivateKeyPairsFromByteArray';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  privParams := keypair.Private as IECPrivateKeyParameters; // for signing
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  Writeln('Public Key Normalized XCoord is: ' +
    pubParams.Q.Normalize.AffineXCoord.ToBigInteger.ToString(16) + sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' +
    pubParams.Q.Normalize.AffineYCoord.ToBigInteger.ToString(16) + sLineBreak);

  Writeln('Private Key D Parameter is: ' + privParams.D.ToString(16) +
    sLineBreak);

  PublicKeyByteArray := pubParams.Q.GetEncoded;
  // using ToByteArray here because bytes are unsigned in Pascal
  PrivateKeyByteArray := privParams.D.ToByteArray;

  RegeneratedPublicKey := TECPublicKeyParameters.Create('ECDSA',
    FCurve.Curve.DecodePoint(PublicKeyByteArray), domain);

  if pubParams.Equals(RegeneratedPublicKey) then
  begin
    Writeln('Public Key Recreation Match With Original Public Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation DOES NOT Match With Original Public Key' +
      sLineBreak);
  end;

  PrivD := TBigInteger.Create(PrivateKeyByteArray);
  RegeneratedPrivateKey := TECPrivateKeyParameters.Create('ECDSA',
    PrivD, domain);

  if privParams.Equals(RegeneratedPrivateKey) then
  begin
    Writeln('Private Key Recreation Match With Original Private Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Private Key Recreation DOES NOT Match With Original Private Key' +
      sLineBreak);
  end;

end;

class procedure TUsageExamples.RecreatePublicKeyFromXAndYCoordByteArray;
var
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
  keypair: IAsymmetricCipherKeyPair;
  pubParams, RegeneratedPublicKey: IECPublicKeyParameters;
  XCoordByteArray, YCoordByteArray: TBytes;
  BigXCoord, BigYCoord, BigXCoordRecreated, BigYCoordRecreated: TBigInteger;
  point: IECPoint;
const
  MethodName = 'RecreatePublicKeyFromXAndYCoordByteArray';
begin

  Writeln('MethodName is: ' + MethodName + sLineBreak);

  domain := TECDomainParameters.Create(FCurve.Curve, FCurve.G, FCurve.N,
    FCurve.H, FCurve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);

  keypair := generator.GenerateKeyPair();
  pubParams := keypair.Public as IECPublicKeyParameters; // for verifying

  Writeln('Algorithm Name is: ' + pubParams.AlgorithmName + sLineBreak);

  BigXCoord := pubParams.Q.Normalize.AffineXCoord.ToBigInteger;
  BigYCoord := pubParams.Q.Normalize.AffineYCoord.ToBigInteger;

  Writeln('Public Key Normalized XCoord is: ' + BigXCoord.ToString(16) +
    sLineBreak);
  Writeln('Public Key Normalized YCoord is: ' + BigYCoord.ToString(16) +
    sLineBreak);

  XCoordByteArray := BigXCoord.ToByteArray;
  YCoordByteArray := BigYCoord.ToByteArray;

  BigXCoordRecreated := TBigInteger.Create(1, XCoordByteArray);
  BigYCoordRecreated := TBigInteger.Create(1, YCoordByteArray);

  point := FCurve.Curve.CreatePoint(BigXCoordRecreated, BigYCoordRecreated);

  RegeneratedPublicKey := TECPublicKeyParameters.Create(point, domain);

  if pubParams.Equals(RegeneratedPublicKey) then
  begin
    Writeln('Public Key Recreation Match With Original Public Key' +
      sLineBreak);
  end
  else
  begin
    Writeln('Public Key Recreation DOES NOT Match With Original Public Key' +
      sLineBreak);
  end;

end;

class constructor TUsageExamples.UsageExamples;
begin
  FRandom := TSecureRandom.Create();
  FCurve := TSecNamedCurves.GetByName(CurveName);
end;

end.
