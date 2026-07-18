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

unit AeadCipherExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  CipherExampleBase;

type
  TAeadCipherExample = class(TCipherExampleBase)
  public
    procedure Run; override;
  end;

implementation

uses
  SysUtils,
  ClpConverters,
  AeadCipherExampleUtilities;

const
  // Add an AEAD cipher by adding a row plus its one-line factory in
  // AeadCipherExampleUtilities. All seven share the native IAeadCipher
  // driver (encrypt/decrypt + AAD + tamper detection).
  AeadSpecs: array[0..6] of TAeadSpec = (
    (DisplayName: 'AES-256-GCM'; KeyByteCount: 32; NonceByteCount: 12; TagBitLength: 128; NewCipher: NewAesGcm),
    (DisplayName: 'AES-256-CCM'; KeyByteCount: 32; NonceByteCount: 11; TagBitLength: 128; NewCipher: NewAesCcm),
    (DisplayName: 'AES-256-EAX'; KeyByteCount: 32; NonceByteCount: 16; TagBitLength: 128; NewCipher: NewAesEax),
    (DisplayName: 'AES-256-OCB'; KeyByteCount: 32; NonceByteCount: 12; TagBitLength: 128; NewCipher: NewAesOcb),
    (DisplayName: 'AES-256-GCM-SIV'; KeyByteCount: 32; NonceByteCount: 12; TagBitLength: 128; NewCipher: NewAesGcmSiv),
    (DisplayName: 'ChaCha20-Poly1305'; KeyByteCount: 32; NonceByteCount: 12; TagBitLength: 128; NewCipher: NewChaChaPoly),
    (DisplayName: 'XChaCha20-Poly1305'; KeyByteCount: 32; NonceByteCount: 24; TagBitLength: 128; NewCipher: NewXChaChaPoly)
  );

procedure TAeadCipherExample.Run;
var
  LPlain, LAad: TBytes;
  LI, LCipherTextLen: Int32;
  LMatched, LTamperRejected: Boolean;
begin
  LogWithLineBreak('--- AEAD cipher example: encrypt/decrypt + AAD + tamper detection ---');
  LPlain := DemoPlaintext;
  LAad := TConverters.ConvertStringToBytes('example-associated-data', TEncoding.UTF8);
  for LI := Low(AeadSpecs) to High(AeadSpecs) do
  begin
    Logger.LogInformation('AEAD: {0} (256-bit key, {1}-bit nonce, {2}-bit tag)',
      [AeadSpecs[LI].DisplayName, IntToStr(AeadSpecs[LI].NonceByteCount * 8),
      IntToStr(AeadSpecs[LI].TagBitLength)]);
    LMatched := TAeadCipherExampleUtilities.AeadRoundtrip(AeadSpecs[LI], LPlain, LAad,
      LCipherTextLen, LTamperRejected);
    ReportAead(AeadSpecs[LI].DisplayName, LMatched, LCipherTextLen, LTamperRejected);
  end;
end;

end.
