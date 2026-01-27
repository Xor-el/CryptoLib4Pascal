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

unit X509ExtensionsTests;

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
  ClpIX509Extension,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TX509ExtensionsTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FOid1, FOid2, FOid3: IDerObjectIdentifier;

    procedure SetUpTestData;

  protected
    procedure SetUp; override;

  published
    procedure TestDuplicateExtensions;
    procedure TestAllowedDuplicateExtensions;
    procedure TestEqualsAndEquivalent;

  end;

implementation

{ TX509ExtensionsTest }

procedure TX509ExtensionsTest.SetUpTestData;
begin
  FOid1 := TDerObjectIdentifier.Create('1.2.1');
  FOid2 := TDerObjectIdentifier.Create('1.2.2');
  FOid3 := TDerObjectIdentifier.Create('1.2.3');
end;

procedure TX509ExtensionsTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

procedure TX509ExtensionsTest.TestDuplicateExtensions;
var
  LName1, LName2: IGeneralName;
  LExtGen, LGenX: IX509ExtensionsGenerator;
  LExts: IX509Extensions;
  LReturnedExtension: IX509Extension;
  LSeq: IAsn1Sequence;
  LBytes: TCryptoLibByteArray;
begin
  LName1 := TGeneralName.Create(TGeneralName.DnsName, 'bc1.local');

  LName2 := TGeneralName.Create(TGeneralName.DnsName, 'bc2.local');

  LExtGen := TX509ExtensionsGenerator.Create();

  LExtGen.AddExtension(TX509Extensions.SubjectAlternativeName, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName1]) as IAsn1EncodableVector) as IDerSequence);

  LExtGen.AddExtension(TX509Extensions.SubjectAlternativeName, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName2]) as IAsn1EncodableVector) as IDerSequence);

  LBytes := LExtGen.Generate().GetEncoded();
  LExts := TX509Extensions.GetInstance(TAsn1Sequence.GetInstance(LBytes));

  LReturnedExtension := LExts.GetExtension(TX509Extensions.SubjectAlternativeName);

  LSeq := TAsn1Sequence.GetInstance(LReturnedExtension.GetParsedValue());

  CheckTrue(TGeneralName.GetInstance(LSeq[0]).Equals(LName1), 'expected name 1');

  CheckTrue(TGeneralName.GetInstance(LSeq[1]).Equals(LName2), 'expected name 2');

  LGenX := TX509ExtensionsGenerator.Create();

  LGenX.AddExtensions(LExts);

  LBytes := LGenX.Generate().GetEncoded();
  LExts := TX509Extensions.GetInstance(TAsn1Sequence.GetInstance(LBytes));

  LReturnedExtension := LExts.GetExtension(TX509Extensions.SubjectAlternativeName);

  LSeq := TAsn1Sequence.GetInstance(LReturnedExtension.GetParsedValue());

  CheckTrue(TGeneralName.GetInstance(LSeq[0]).Equals(LName1), 'expected name 1');

  CheckTrue(TGeneralName.GetInstance(LSeq[1]).Equals(LName2), 'expected name 2');
end;

procedure TX509ExtensionsTest.TestAllowedDuplicateExtensions;
var
  LName1, LName2: IGeneralName;
  LExtGen: IX509ExtensionsGenerator;
begin
  LName1 := TGeneralName.Create(TGeneralName.DnsName, 'bc1.local');

  LName2 := TGeneralName.Create(TGeneralName.DnsName, 'bc2.local');

  LExtGen := TX509ExtensionsGenerator.Create();

  LExtGen.AddExtension(TX509Extensions.SubjectAlternativeName, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName1]) as IAsn1EncodableVector) as IDerSequence);

  LExtGen.AddExtension(TX509Extensions.SubjectAlternativeName, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName2]) as IAsn1EncodableVector) as IDerSequence);

  LExtGen.AddExtension(TX509Extensions.IssuerAlternativeName, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName1]) as IAsn1EncodableVector) as IDerSequence);

  LExtGen.AddExtension(TX509Extensions.IssuerAlternativeName, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName2]) as IAsn1EncodableVector) as IDerSequence);

  LExtGen.AddExtension(TX509Extensions.SubjectDirectoryAttributes, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName1]) as IAsn1EncodableVector) as IDerSequence);

  LExtGen.AddExtension(TX509Extensions.SubjectDirectoryAttributes, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName2]) as IAsn1EncodableVector) as IDerSequence);

  LExtGen.AddExtension(TX509Extensions.CertificateIssuer, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName1]) as IAsn1EncodableVector) as IDerSequence);

  LExtGen.AddExtension(TX509Extensions.CertificateIssuer, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName2]) as IAsn1EncodableVector) as IDerSequence);

  LExtGen.AddExtension(TX509Extensions.AuditIdentity, False,
    TDerSequence.Create(TAsn1EncodableVector.Create([LName1]) as IAsn1EncodableVector) as IDerSequence);

  try
    LExtGen.AddExtension(TX509Extensions.AuditIdentity, False,
      TDerSequence.Create(TAsn1EncodableVector.Create([LName2]) as IAsn1EncodableVector) as IDerSequence);
    Fail('Expected exception, not a white listed duplicate.');
  except
    // ok - expected exception
  end;
end;

procedure TX509ExtensionsTest.TestEqualsAndEquivalent;
var
  LGen: IX509ExtensionsGenerator;
  LExt1, LExt2: IX509Extensions;
  LBytes20, LBytes22: TCryptoLibByteArray;
begin
  LGen := TX509ExtensionsGenerator.Create();

  System.SetLength(LBytes20, 20);

  LGen.AddExtension(FOid1, True, LBytes20);

  LGen.AddExtension(FOid2, True, LBytes20);

  LExt1 := LGen.Generate();

  LExt2 := LGen.Generate();

  CheckTrue(LExt1.Equals(LExt2), 'Equals test failed');

  LGen.Reset();

  LGen.AddExtension(FOid2, True, LBytes20);

  LGen.AddExtension(FOid1, True, LBytes20);

  LExt2 := LGen.Generate();

  CheckFalse(LExt1.Equals(LExt2), 'inequality test failed');

  CheckTrue(LExt1.Equivalent(LExt2), 'equivalence true failed');

  LGen.Reset();

  System.SetLength(LBytes22, 22);

  LGen.AddExtension(FOid1, True, LBytes22);

  LGen.AddExtension(FOid2, True, LBytes20);

  LExt2 := LGen.Generate();

  CheckFalse(LExt1.Equals(LExt2), 'inequality 1 failed');

  CheckFalse(LExt1.Equivalent(LExt2), 'non-equivalence 1 failed');

  LGen.Reset();

  LGen.AddExtension(FOid3, True, LBytes20);

  LGen.AddExtension(FOid2, True, LBytes20);

  LExt2 := LGen.Generate();

  CheckFalse(LExt1.Equals(LExt2), 'inequality 2 failed');

  CheckFalse(LExt1.Equivalent(LExt2), 'non-equivalence 2 failed');

  try
    LGen.AddExtension(FOid2, True, LBytes20);
    Fail('repeated oid');
  except
    on E: EArgumentCryptoLibException do
    begin
      if E.Message <> 'extension 1.2.2 already added' then
        Fail(Format('wrong exception on repeated oid: %s', [E.Message]));
    end;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TX509ExtensionsTest);
{$ELSE}
RegisterTest(TX509ExtensionsTest.Suite);
{$ENDIF FPC}

end.
