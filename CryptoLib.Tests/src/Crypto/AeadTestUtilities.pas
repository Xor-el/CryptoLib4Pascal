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

unit AeadTestUtilities;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpCryptoLibTypes;

type
  TAeadTestUtilities = class sealed(TObject)
  public
    class procedure TestTampering(const ATestName: string;
      const ACipher: IAeadCipher; const AParameters: ICipherParameters); static;

    class function ReuseKey(const AParameters: IAeadParameters)
      : IAeadParameters; static;
  end;

implementation

{ TAeadTestUtilities }

class procedure TAeadTestUtilities.TestTampering(const ATestName: string;
  const ACipher: IAeadCipher; const AParameters: ICipherParameters);
var
  LPlaintext, LCiphertext, LTampered, LTruncated, LOutput: TCryptoLibByteArray;
  LLen, LMacLength: Int32;
begin
  // prepare plaintext 0..999
  System.SetLength(LPlaintext, 1000);
  for LLen := 0 to System.Pred(System.Length(LPlaintext)) do
  begin
    LPlaintext[LLen] := Byte(LLen);
  end;

  // encrypt once
  ACipher.Init(True, AParameters);
  System.SetLength(LCiphertext, ACipher.GetOutputSize(System.Length(LPlaintext)));
  LLen := ACipher.ProcessBytes(LPlaintext, 0, System.Length(LPlaintext),
    LCiphertext, 0);
  LLen := LLen + ACipher.DoFinal(LCiphertext, LLen);

  // cache current tag length
  LMacLength := System.Length(ACipher.GetMac);

  // Test tampering with a single byte
  ACipher.Init(False, AParameters);
  System.SetLength(LTampered, LLen);
  System.Move(LCiphertext[0], LTampered[0], LLen);
  LTampered[0] := Byte(LTampered[0] + 1);

  System.SetLength(LOutput, System.Length(LPlaintext));
  ACipher.ProcessBytes(LTampered, 0, LLen, LOutput, 0);
  try
    ACipher.DoFinal(LOutput, 0);
    raise Exception.CreateFmt('%s : tampering of ciphertext not detected.',
      [ATestName]);
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      // expected
    end;
  end;

  // Test truncation of ciphertext to < tag length
  ACipher.Init(False, AParameters);
  if LMacLength > 0 then
  begin
    System.SetLength(LTruncated, LMacLength - 1);
    System.Move(LCiphertext[0], LTruncated[0], System.Length(LTruncated));

    ACipher.ProcessBytes(LTruncated, 0, System.Length(LTruncated), LOutput, 0);
    try
      ACipher.DoFinal(LOutput, 0);
      raise Exception.CreateFmt('%s : tampering of ciphertext not detected.',
        [ATestName]);
    except
      on E: EInvalidCipherTextCryptoLibException do
      begin
        // expected
      end;
    end;
  end;
end;

class function TAeadTestUtilities.ReuseKey(const AParameters: IAeadParameters)
  : IAeadParameters;
begin
  Result := TAeadParameters.Create(nil, AParameters.MacSize,
    AParameters.GetNonce, AParameters.GetAssociatedText);
end;

end.

