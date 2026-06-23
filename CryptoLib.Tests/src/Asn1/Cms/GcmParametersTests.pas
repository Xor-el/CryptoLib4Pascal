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

unit GcmParametersTests;

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
  ClpAsn1Objects,
  ClpIAsn1Core,
  ClpICmsAsn1Objects,
  ClpCmsAsn1Objects,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TGcmParametersTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function Seq(AIcvLen: Int32): IAsn1Encodable;
    function SeqNoIcv: IAsn1Encodable;
    function Nonce12: TCryptoLibByteArray;

  published
    procedure TestDefaultIcvLen;
    procedure TestInvalidIcvLen;
    procedure TestValidIcvLen;
  end;

implementation

function TGcmParametersTest.Nonce12: TCryptoLibByteArray;
begin
  Result := TCryptoLibByteArray.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
end;

function TGcmParametersTest.Seq(AIcvLen: Int32): IAsn1Encodable;
begin
  Result := TDerSequence.Create([
    TDerOctetString.FromContents(Nonce12),
    TDerInteger.ValueOf(AIcvLen)
  ]);
end;

function TGcmParametersTest.SeqNoIcv: IAsn1Encodable;
begin
  Result := TDerSequence.Create([TDerOctetString.FromContents(Nonce12)]);
end;

procedure TGcmParametersTest.TestDefaultIcvLen;
begin
  CheckEquals(12, TGcmParameters.GetInstance(SeqNoIcv).IcvLen);
end;

procedure TGcmParametersTest.TestInvalidIcvLen;
const
  InvalidIcvLens: array[0..3] of Int32 = (-1, 0, 11, 17);
var
  LI: Int32;
begin
  for LI := 0 to High(InvalidIcvLens) do
  begin
    try
      TGcmParameters.GetInstance(Seq(InvalidIcvLens[LI]));
      Fail('invalid ICV length not rejected on parse');
    except
      on E: Exception do
      begin
        // expected
      end;
    end;

    try
      TGcmParameters.Create(Nonce12, InvalidIcvLens[LI]);
      Fail('invalid ICV length not rejected on construct');
    except
      on E: Exception do
      begin
        // expected
      end;
    end;
  end;
end;

procedure TGcmParametersTest.TestValidIcvLen;
const
  ValidIcvLens: array[0..4] of Int32 = (12, 13, 14, 15, 16);
var
  LI: Int32;
begin
  for LI := 0 to High(ValidIcvLens) do
  begin
    CheckEquals(ValidIcvLens[LI], TGcmParameters.GetInstance(Seq(ValidIcvLens[LI])).IcvLen);
    CheckEquals(ValidIcvLens[LI], (TGcmParameters.Create(Nonce12, ValidIcvLens[LI]) as IGcmParameters).IcvLen);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TGcmParametersTest);
{$ELSE}
  RegisterTest(TGcmParametersTest.Suite);
{$ENDIF FPC}

end.
