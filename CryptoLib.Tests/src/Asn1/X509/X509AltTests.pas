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

unit X509AltTests;

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
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpX509ExtensionsGenerator,
  ClpIX509ExtensionsGenerator,
  ClpPkcsObjectIdentifiers,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TX509AltTest = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestX509AltTypes;

  end;

implementation

{ TX509AltTest }

procedure TX509AltTest.TestX509AltTypes;
var
  LSubAlt: ISubjectAltPublicKeyInfo;
  LSigValAlt: IAltSignatureValue;
  LSigAlgAlt, LSigAlgAlt2: IAltSignatureAlgorithm;
  LExtGen: IX509ExtensionsGenerator;
  LExts: IX509Extensions;
  LBytes: TCryptoLibByteArray;
begin
  LBytes := DecodeHex('0102030405060708090807060504030201');
  LSubAlt := TSubjectAltPublicKeyInfo.Create(
    TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.RsaEncryption, TDerNull.Instance),
    TDerBitString.Create(LBytes));

  LSigValAlt := TAltSignatureValue.Create(LBytes);

  LSigAlgAlt := TAltSignatureAlgorithm.Create(
    TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.MD5WithRsaEncryption, TDerNull.Instance));

  LSigAlgAlt2 := TAltSignatureAlgorithm.Create(
    TPkcsObjectIdentifiers.MD5WithRsaEncryption, TDerNull.Instance);

  CheckTrue(LSigAlgAlt.Equals(LSigAlgAlt2), 'AltSignatureAlgorithm instances should be equal');

  LExtGen := TX509ExtensionsGenerator.Create();

  LExtGen.AddExtension(TX509Extensions.SubjectAltPublicKeyInfo, False, LSubAlt);

  LExtGen.AddExtension(TX509Extensions.AltSignatureAlgorithm, False, LSigAlgAlt);

  LExtGen.AddExtension(TX509Extensions.AltSignatureValue, False, LSigValAlt);


  LExts := LExtGen.Generate();

  CheckTrue(LSubAlt.Equals(TSubjectAltPublicKeyInfo.FromExtensions(LExts)), 'SubjectAltPublicKeyInfo from extensions should match');

  CheckTrue(LSigAlgAlt.Equals(TAltSignatureAlgorithm.FromExtensions(LExts)), 'AltSignatureAlgorithm from extensions should match');

  CheckTrue(LSigValAlt.Equals(TAltSignatureValue.FromExtensions(LExts)), 'AltSignatureValue from extensions should match');

  CheckTrue(LSubAlt.Equals(TSubjectAltPublicKeyInfo.GetInstance(LSubAlt.GetEncoded())), 'SubjectAltPublicKeyInfo round-trip should match');

  CheckTrue(LSigAlgAlt.Equals(TAltSignatureAlgorithm.GetInstance(LSigAlgAlt.GetEncoded())), 'AltSignatureAlgorithm round-trip should match');

  CheckTrue(LSigValAlt.Equals(TAltSignatureValue.GetInstance(LSigValAlt.GetEncoded())), 'AltSignatureValue round-trip should match');

  CheckTrue(LSubAlt.Equals(TSubjectAltPublicKeyInfo.GetInstance(TDerTaggedObject.Create(1, LSubAlt), True)), 'SubjectAltPublicKeyInfo from tagged should match');

  CheckTrue(LSigAlgAlt.Equals(TAltSignatureAlgorithm.GetInstance(TDerTaggedObject.Create(1, LSigAlgAlt), True)), 'AltSignatureAlgorithm from tagged should match');

  CheckTrue(LSigValAlt.Equals(TAltSignatureValue.GetInstance(TDerTaggedObject.Create(1, LSigValAlt), True)), 'AltSignatureValue from tagged should match');
end;

initialization

{$IFDEF FPC}
RegisterTest(TX509AltTest);
{$ELSE}
RegisterTest(TX509AltTest.Suite);
{$ENDIF FPC}

end.
