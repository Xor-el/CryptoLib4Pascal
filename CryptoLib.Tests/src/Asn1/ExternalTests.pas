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

unit ExternalTests;

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
  ClpAsn1Core,
  ClpAsn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Tests used to verify correct decoding of the EXTERNAL type.
  /// </summary>
  TExternalTest = class(TCryptoLibAlgorithmTestCase)
  published
    /// <summary>
    /// Malformed EXTERNAL-style input must surface as <see cref="EAsn1CryptoLibException"/>, not plain I/O.
    /// </summary>
    procedure TestConstructorInvalidCast;
  end;

implementation

{ TExternalTest }

procedure TExternalTest.TestConstructorInvalidCast;
var
  LBadEncoding: TCryptoLibByteArray;
begin
  // 6 bytes: SEQUENCE { CONSTRUCTED(0x28) { SEQUENCE {} } } — intentionally malformed; decode must raise ASN.1 layer errors.
  System.SetLength(LBadEncoding, 6);
  LBadEncoding[0] := $30;
  LBadEncoding[1] := $04;
  LBadEncoding[2] := $28;
  LBadEncoding[3] := $02;
  LBadEncoding[4] := $30;
  LBadEncoding[5] := $00;
  try
    TAsn1Object.FromByteArray(LBadEncoding);
    Fail('EAsn1CryptoLibException expected');
  except
    on E: EAsn1CryptoLibException do
      ; // expected
    on E: EIOCryptoLibException do
      Fail('EAsn1CryptoLibException expected; got EIOCryptoLibException: ' + E.Message);
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TExternalTest);
{$ELSE}
RegisterTest(TExternalTest.Suite);
{$ENDIF FPC}

end.
