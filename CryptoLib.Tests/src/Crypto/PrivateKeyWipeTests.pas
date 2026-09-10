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

unit PrivateKeyWipeTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIKeyGenerationParameters,
  ClpMlKemParameters,
  ClpIMlKemParameters,
  ClpMlKemGenerators,
  ClpMlDsaParameters,
  ClpIMlDsaParameters,
  ClpMlDsaGenerators,
  ClpNistObjectIdentifiers,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// A private-key parameter object zeroizes its secret material when the last reference releases.
  /// The private key exposes its secret buffer by reference (GetEncoding / GetK / GetS1 / GetT0), so a
  /// retained reference keeps the buffer alive past the object's destruction and observes the wipe.
  /// </summary>
  TPrivateKeyWipeTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRandom: ISecureRandom;
    function AllZero(const ABuf: TCryptoLibByteArray): Boolean;
    // Each helper acquires a fresh key, captures its secret buffer(s) by reference, and returns.
    // On return every key reference (including the compiler's hidden interface temporaries) is
    // finalized, so the key is destroyed and its destructor has wiped the captured buffer(s), which
    // outlive the key because the caller still holds them.
    function GenMlKemPrivateEncoding: TCryptoLibByteArray;
    procedure GenMlDsaPrivateSecrets(out AK, AS1, AT0: TCryptoLibByteArray);
  protected
    procedure SetUp; override;
  published
    procedure TestMlKemPrivateKeyWipedOnDestroy;
    procedure TestMlDsaPrivateKeyWipedOnDestroy;
  end;

implementation

{ TPrivateKeyWipeTest }

procedure TPrivateKeyWipeTest.SetUp;
begin
  inherited SetUp;
  FRandom := TSecureRandom.Create() as ISecureRandom;
end;

function TPrivateKeyWipeTest.AllZero(const ABuf: TCryptoLibByteArray): Boolean;
var
  LI: Int32;
begin
  Result := True;
  for LI := 0 to System.Length(ABuf) - 1 do
    if ABuf[LI] <> 0 then
      Exit(False);
end;

function TPrivateKeyWipeTest.GenMlKemPrivateEncoding: TCryptoLibByteArray;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPriv: IMlKemPrivateKeyParameters;
begin
  LKpg := TMlKemKeyPairGenerator.Create;
  LKpg.Init(TMlKemKeyGenerationParameters.Create(FRandom, TMlKemParameters.MlKem512)
    as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPriv := LKp.Private as IMlKemPrivateKeyParameters;

  // the internal encoding buffer, by reference (retaining it keeps the buffer alive after destroy)
  Result := LPriv.GetEncoding;
  CheckTrue(System.Length(Result) > 0, 'the private key encoding should be present');
  CheckFalse(AllZero(Result), 'precondition: the private key encoding is non-zero');
end;

procedure TPrivateKeyWipeTest.GenMlDsaPrivateSecrets(out AK, AS1, AT0: TCryptoLibByteArray);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPriv: IMlDsaPrivateKeyParameters;
begin
  LKpg := TMlDsaKeyPairGenerator.Create;
  LKpg.Init(TMlDsaKeyGenerationParameters.Create(FRandom, TNistObjectIdentifiers.IdMlDsa44)
    as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPriv := LKp.Private as IMlDsaPrivateKeyParameters;

  // secret components, by reference
  AK := LPriv.GetK;
  AS1 := LPriv.GetS1;
  AT0 := LPriv.GetT0;
  CheckFalse(AllZero(AK), 'precondition: K is non-zero');
  CheckFalse(AllZero(AS1), 'precondition: s1 is non-zero');
  CheckFalse(AllZero(AT0), 'precondition: t0 is non-zero');
end;

procedure TPrivateKeyWipeTest.TestMlKemPrivateKeyWipedOnDestroy;
var
  LEncoding: TCryptoLibByteArray;
begin
  LEncoding := GenMlKemPrivateEncoding;
  // the helper has returned, so the key is destroyed; its destructor must have wiped the encoding
  CheckTrue(AllZero(LEncoding), 'the private key encoding must be wiped when the key is destroyed');
end;

procedure TPrivateKeyWipeTest.TestMlDsaPrivateKeyWipedOnDestroy;
var
  LK, LS1, LT0: TCryptoLibByteArray;
begin
  GenMlDsaPrivateSecrets(LK, LS1, LT0);
  // the helper has returned, so the key is destroyed; its destructor must have wiped the secrets
  CheckTrue(AllZero(LK), 'K must be wiped when the key is destroyed');
  CheckTrue(AllZero(LS1), 's1 must be wiped when the key is destroyed');
  CheckTrue(AllZero(LT0), 't0 must be wiped when the key is destroyed');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TPrivateKeyWipeTest);
{$ELSE}
  RegisterTest(TPrivateKeyWipeTest.Suite);
{$ENDIF FPC}

end.
