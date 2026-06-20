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

unit DigestExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpConverters,
  ClpIArgon2ParametersGenerator,
  ExampleBase,
  DigestExampleUtilities;

type
  TDigestExample = class(TExampleBase)
  private
    procedure RunDigestDemos;
  public
    procedure Run; override;
  end;

implementation

procedure TDigestExample.RunDigestDemos;
var
  LInput, LKey, LMsg, LPassword, LSalt: TBytes;
begin
  LInput := TConverters.ConvertStringToBytes('Hello CryptoLib', TEncoding.UTF8);
  LKey := TConverters.ConvertStringToBytes('secret-key', TEncoding.UTF8);
  LMsg := TConverters.ConvertStringToBytes('message to authenticate', TEncoding.UTF8);
  LPassword := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  LSalt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);

  LogWithLineBreak('--- Digest example: Hash ---');
  TDigestExampleUtilities.RunHash('SHA-256', LInput);
  LogWithLineBreak('--- Digest example: HMAC ---');
  TDigestExampleUtilities.RunHmac('HMAC-SHA256', LKey, LMsg);
  LogWithLineBreak('--- Digest example: Key derivation (PBKDF2) ---');
  TDigestExampleUtilities.RunPbkdf2('SHA-256', LPassword, LSalt, 10000, 256,
    'PBKDF2-HMAC-SHA-256 (10000 iters)');
  LogWithLineBreak('--- Digest example: Key derivation (Argon2d) ---');
  TDigestExampleUtilities.RunArgon2(TCryptoLibArgon2Type.Argon2D, LPassword, LSalt,
    2, 65536, 1, 256, 'Argon2d (2 iters, 64 MiB, 1 lane)');
  LogWithLineBreak('--- Digest example: Key derivation (Argon2i) ---');
  TDigestExampleUtilities.RunArgon2(TCryptoLibArgon2Type.Argon2I, LPassword, LSalt,
    2, 65536, 1, 256, 'Argon2i (2 iters, 64 MiB, 1 lane)');
  LogWithLineBreak('--- Digest example: Key derivation (Argon2id) ---');
  TDigestExampleUtilities.RunArgon2(TCryptoLibArgon2Type.Argon2ID, LPassword, LSalt,
    2, 65536, 1, 256, 'Argon2id (2 iters, 64 MiB, 1 lane)');
  LogWithLineBreak('--- Digest example: Key derivation (Scrypt) ---');
  TDigestExampleUtilities.RunScrypt(LPassword, LSalt, 16384, 8, 1, 256,
    'Scrypt (N=16384, r=8, p=1)');
end;

procedure TDigestExample.Run;
begin
  RunDigestDemos;
end;

end.
