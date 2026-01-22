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

unit KeyUsageTests;

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
  CryptoLibTestBase;

type

  TKeyUsageTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    procedure TestFlagValueCorrect(ABitNo: Int32; AValue: Int32);

  published
    procedure TestDigitalSignature;
    procedure TestNonRepudiation;
    procedure TestKeyEncipherment;
    procedure TestDataEncipherment;
    procedure TestKeyAgreement;
    procedure TestKeyCertSign;
    procedure TestCrlSign;
    procedure TestEncipherOnly;
    procedure TestDecipherOnly;

  end;

implementation

{ TKeyUsageTest }

procedure TKeyUsageTest.TestFlagValueCorrect(ABitNo: Int32; AValue: Int32);
const
  // bits array with bit values
  Bits: array[0..31] of Int32 = (
    (1 shl 7), (1 shl 6), (1 shl 5), (1 shl 4), (1 shl 3), (1 shl 2), (1 shl 1), (1 shl 0),
    (1 shl 15), (1 shl 14), (1 shl 13), (1 shl 12), (1 shl 11), (1 shl 10), (1 shl 9), (1 shl 8),
    (1 shl 23), (1 shl 22), (1 shl 21), (1 shl 20), (1 shl 19), (1 shl 18), (1 shl 17), (1 shl 16),
    (1 shl 31), (1 shl 30), (1 shl 29), (1 shl 28), (1 shl 27), (1 shl 26), (1 shl 25), (1 shl 24)
  );
begin
  if Bits[ABitNo] <> AValue then
  begin
    Fail(Format('bit value %d wrong', [ABitNo]));
  end;
end;

procedure TKeyUsageTest.TestDigitalSignature;
begin
  TestFlagValueCorrect(0, TKeyUsage.DigitalSignature);
end;

procedure TKeyUsageTest.TestNonRepudiation;
begin
  TestFlagValueCorrect(1, TKeyUsage.NonRepudiation);
end;

procedure TKeyUsageTest.TestKeyEncipherment;
begin
  TestFlagValueCorrect(2, TKeyUsage.KeyEncipherment);
end;

procedure TKeyUsageTest.TestDataEncipherment;
begin
  TestFlagValueCorrect(3, TKeyUsage.DataEncipherment);
end;

procedure TKeyUsageTest.TestKeyAgreement;
begin
  TestFlagValueCorrect(4, TKeyUsage.KeyAgreement);
end;

procedure TKeyUsageTest.TestKeyCertSign;
begin
  TestFlagValueCorrect(5, TKeyUsage.KeyCertSign);
end;

procedure TKeyUsageTest.TestCrlSign;
begin
  TestFlagValueCorrect(6, TKeyUsage.CrlSign);
end;

procedure TKeyUsageTest.TestEncipherOnly;
begin
  TestFlagValueCorrect(7, TKeyUsage.EncipherOnly);
end;

procedure TKeyUsageTest.TestDecipherOnly;
begin
  TestFlagValueCorrect(8, TKeyUsage.DecipherOnly);
end;

initialization

{$IFDEF FPC}
RegisterTest(TKeyUsageTest);
{$ELSE}
RegisterTest(TKeyUsageTest.Suite);
{$ENDIF FPC}

end.
