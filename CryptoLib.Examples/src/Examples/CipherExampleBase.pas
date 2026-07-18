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

unit CipherExampleBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpConverters,
  ExampleBase;

type
  /// <summary>
  /// One non-AEAD symmetric cipher demo row. Block and stream ciphers are
  /// driven identically (buffered cipher + ParametersWithIV), so the same
  /// record describes both - only the data differs.
  /// </summary>
  TSymmetricSpec = record
    Algorithm: string;
    DisplayName: string;
    KeyByteCount: Int32;
    IvByteCount: Int32;
  end;

  /// <summary>
  /// Shared reporting for the cipher example family: uniform success/failure
  /// logging (and the AEAD tamper-detection line), plus the demo plaintext.
  /// </summary>
  TCipherExampleBase = class(TExampleBase)
  protected
    function DemoPlaintext: TBytes;
    procedure ReportRoundtrip(const ADisplayName: string; AMatched: Boolean;
      ACipherTextLen: Int32);
    procedure ReportAead(const ADisplayName: string; AMatched: Boolean;
      ACipherTextLen: Int32; ATamperRejected: Boolean);
  end;

  /// <summary>
  /// Base for the block and stream examples: iterates a table of
  /// <see cref="TSymmetricSpec"/> rows through the shared non-AEAD driver
  /// and reports each. Subclasses supply only the heading and the table.
  /// </summary>
  TSymmetricCipherExampleBase = class(TCipherExampleBase)
  protected
    procedure RunSpecs(const AHeading: string; const ASpecs: array of TSymmetricSpec);
  end;

implementation

uses
  CipherExampleUtilities;

function TCipherExampleBase.DemoPlaintext: TBytes;
begin
  Result := TConverters.ConvertStringToBytes('Secret message', TEncoding.UTF8);
end;

procedure TCipherExampleBase.ReportRoundtrip(const ADisplayName: string;
  AMatched: Boolean; ACipherTextLen: Int32);
begin
  if AMatched then
  begin
    Logger.LogInformation('{0} encrypted length: {1}', [ADisplayName, IntToStr(ACipherTextLen)]);
    Logger.LogInformation('{0} decrypt match: success.', [ADisplayName]);
  end
  else
    Logger.LogError('{0} encrypt/decrypt roundtrip failed.', [ADisplayName]);
end;

procedure TCipherExampleBase.ReportAead(const ADisplayName: string;
  AMatched: Boolean; ACipherTextLen: Int32; ATamperRejected: Boolean);
begin
  ReportRoundtrip(ADisplayName, AMatched, ACipherTextLen);
  if not AMatched then
    Exit;
  if ATamperRejected then
    Logger.LogInformation('{0} tamper detected: success (modified ciphertext rejected).', [ADisplayName])
  else
    Logger.LogError('{0} tamper NOT detected: modified ciphertext was accepted.', [ADisplayName]);
end;

procedure TSymmetricCipherExampleBase.RunSpecs(const AHeading: string;
  const ASpecs: array of TSymmetricSpec);
var
  LPlain: TBytes;
  LI, LCipherTextLen: Int32;
  LMatched: Boolean;
begin
  LogWithLineBreak(AHeading);
  LPlain := DemoPlaintext;
  for LI := Low(ASpecs) to High(ASpecs) do
  begin
    Logger.LogInformation('Cipher: {0} ({1})', [ASpecs[LI].DisplayName, ASpecs[LI].Algorithm]);
    LMatched := TCipherExampleUtilities.NonAeadRoundtripMatches(ASpecs[LI].Algorithm,
      ASpecs[LI].KeyByteCount, ASpecs[LI].IvByteCount, LPlain, LCipherTextLen);
    ReportRoundtrip(ASpecs[LI].DisplayName, LMatched, LCipherTextLen);
  end;
end;

end.
