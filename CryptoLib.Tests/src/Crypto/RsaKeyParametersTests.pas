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

unit RsaKeyParametersTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBigInteger,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpIAsymmetricKeyParameter,
  CryptoLibTestBase;

type

  // GetHashCode must fold in both the modulus and the exponent: two keys that differ in
  // either field must hash differently, and equal keys must hash equally.
  TRsaKeyParametersTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    // real RSA test-vector moduli (also used in RSATest), needed because TRsaKeyParameters
    // validates its modulus (rejects small prime factors, requires it be composite, etc.)
    function Modulus1: TBigInteger;
    function Modulus2: TBigInteger;
    function Exponent1: TBigInteger;
    function Exponent2: TBigInteger;
  published
    procedure TestHashCodeDiffersWhenOnlyExponentDiffers;
    procedure TestHashCodeDiffersWhenOnlyModulusDiffers;
    procedure TestHashCodeMatchesWhenEqual;
    // Equals through the base IAsymmetricKeyParameter reference must compare by value, not just
    // the public/private flag: two distinct public keys are equal iff their key material matches.
    procedure TestBaseInterfaceEqualsComparesValue;
  end;

implementation

{ TRsaKeyParametersTest }

function TRsaKeyParametersTest.Modulus1: TBigInteger;
begin
  Result := TBigInteger.Create(
    'b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2' +
    'b6543165a040c606887420e33d91ed7ed7', 16);
end;

function TRsaKeyParametersTest.Modulus2: TBigInteger;
begin
  Result := TBigInteger.Create(
    '0100000000000000000000000000000000bba2d15dbb303c8a21c5ebbcbae52b7125087920dd7cdf358ea119fd66f' +
    'b064012ec8ce692f0a0b8e8321b041acd40b7', 16);
end;

function TRsaKeyParametersTest.Exponent1: TBigInteger;
begin
  Result := TBigInteger.Create('11', 16);
end;

function TRsaKeyParametersTest.Exponent2: TBigInteger;
begin
  Result := TBigInteger.Create('03', 16);
end;

procedure TRsaKeyParametersTest.TestHashCodeDiffersWhenOnlyExponentDiffers;
var
  LA, LB: IRsaKeyParameters;
begin
  LA := TRsaKeyParameters.Create(False, Modulus1, Exponent1);
  LB := TRsaKeyParameters.Create(False, Modulus1, Exponent2);

  CheckFalse(LA.Equals(LB), 'keys differing only in exponent must not be equal');
  CheckFalse(LA.GetHashCode() = LB.GetHashCode(),
    'keys differing only in exponent must not share a hash code');
end;

procedure TRsaKeyParametersTest.TestHashCodeDiffersWhenOnlyModulusDiffers;
var
  LA, LB: IRsaKeyParameters;
begin
  LA := TRsaKeyParameters.Create(False, Modulus1, Exponent1);
  LB := TRsaKeyParameters.Create(False, Modulus2, Exponent1);

  CheckFalse(LA.Equals(LB), 'keys differing only in modulus must not be equal');
  CheckFalse(LA.GetHashCode() = LB.GetHashCode(),
    'keys differing only in modulus must not share a hash code');
end;

procedure TRsaKeyParametersTest.TestHashCodeMatchesWhenEqual;
var
  LA, LB: IRsaKeyParameters;
begin
  LA := TRsaKeyParameters.Create(False, Modulus1, Exponent1);
  LB := TRsaKeyParameters.Create(False, Modulus1, Exponent1);

  CheckTrue(LA.Equals(LB), 'keys with the same modulus and exponent must be equal');
  CheckEquals(LA.GetHashCode(), LB.GetHashCode(), 'equal keys must share a hash code');
end;

procedure TRsaKeyParametersTest.TestBaseInterfaceEqualsComparesValue;
var
  LA, LB, LC: IAsymmetricKeyParameter;
begin
  // held as the base interface: two distinct public keys with identical material are equal,
  // and two public keys that differ in material are not (a flag-only compare would say equal)
  LA := TRsaKeyParameters.Create(False, Modulus1, Exponent1);
  LB := TRsaKeyParameters.Create(False, Modulus1, Exponent1);
  LC := TRsaKeyParameters.Create(False, Modulus2, Exponent1);
  CheckTrue(LA.Equals(LB), 'equal key material must compare equal through the base interface');
  CheckFalse(LA.Equals(LC), 'different key material must not compare equal (not a flag-only check)');
  CheckTrue(LA.Equals(LA), 'a key equals itself');
  CheckFalse(LA.Equals(nil), 'a key does not equal nil');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TRsaKeyParametersTest);
{$ELSE}
  RegisterTest(TRsaKeyParametersTest.Suite);
{$ENDIF FPC}

end.
