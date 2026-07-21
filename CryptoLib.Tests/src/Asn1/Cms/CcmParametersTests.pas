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

unit CcmParametersTests;

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
  ClpCryptoLibExceptions,
  CryptoLibTestBase;

type
  TCcmParametersTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function Seq(AIcvLen: Int32): IAsn1Encodable;
    function SeqNoIcv: IAsn1Encodable;
    function Nonce12: TCryptoLibByteArray;

  published
    procedure TestDefaultIcvLen;
    procedure TestInvalidIcvLen;
    procedure TestValidIcvLen;
    procedure TestIcvLenOutsideInt32Range;
  end;

implementation

function TCcmParametersTest.Nonce12: TCryptoLibByteArray;
begin
  Result := TCryptoLibByteArray.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
end;

function TCcmParametersTest.Seq(AIcvLen: Int32): IAsn1Encodable;
begin
  Result := TDerSequence.Create([
    TDerOctetString.FromContents(Nonce12),
    TDerInteger.ValueOf(AIcvLen)
  ]);
end;

function TCcmParametersTest.SeqNoIcv: IAsn1Encodable;
begin
  Result := TDerSequence.Create([TDerOctetString.FromContents(Nonce12)]);
end;

procedure TCcmParametersTest.TestDefaultIcvLen;
begin
  CheckEquals(12, TCcmParameters.GetInstance(SeqNoIcv).IcvLen);
end;

procedure TCcmParametersTest.TestInvalidIcvLen;
const
  InvalidIcvLens: array[0..11] of Int32 = (-1, 0, 2, 3, 5, 7, 9, 11, 13, 15, 17, 18);
var
  LI: Int32;
begin
  for LI := 0 to High(InvalidIcvLens) do
  begin
    try
      TCcmParameters.GetInstance(Seq(InvalidIcvLens[LI]));
      Fail('invalid ICV length not rejected on parse');
    except
      on E: Exception do
      begin
        // expected
      end;
    end;

    try
      TCcmParameters.Create(Nonce12, InvalidIcvLens[LI]);
      Fail('invalid ICV length not rejected on construct');
    except
      on E: Exception do
      begin
        // expected
      end;
    end;
  end;
end;

procedure TCcmParametersTest.TestValidIcvLen;
const
  ValidIcvLens: array[0..6] of Int32 = (4, 6, 8, 10, 12, 14, 16);
var
  LI: Int32;
begin
  for LI := 0 to High(ValidIcvLens) do
  begin
    CheckEquals(ValidIcvLens[LI], TCcmParameters.GetInstance(Seq(ValidIcvLens[LI])).IcvLen);
    CheckEquals(ValidIcvLens[LI], (TCcmParameters.Create(Nonce12, ValidIcvLens[LI]) as ICcmParameters).IcvLen);
  end;
end;

procedure TCcmParametersTest.TestIcvLenOutsideInt32Range;
var
  LSeq: IAsn1Encodable;
begin
  // An ICVlen INTEGER wider than Int32 must surface as a controlled argument
  // error, not an arithmetic exception leaking from integer extraction.
  LSeq := TDerSequence.Create([
    TDerOctetString.FromContents(Nonce12),
    TDerInteger.ValueOf(Int64($100000000))
  ]);
  try
    TCcmParameters.GetInstance(LSeq);
    Fail('out-of-Int32 ICV length not rejected on parse');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TCcmParametersTest);
{$ELSE}
  RegisterTest(TCcmParametersTest.Suite);
{$ENDIF FPC}

end.
