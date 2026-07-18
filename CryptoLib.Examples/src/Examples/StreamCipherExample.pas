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

unit StreamCipherExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  CipherExampleBase;

type
  TStreamCipherExample = class(TSymmetricCipherExampleBase)
  public
    procedure Run; override;
  end;

implementation

const
  // Raw stream ciphers (no authentication). Add one by adding a row; each
  // is driven through the same non-AEAD roundtrip as the block ciphers.
  StreamSpecs: array[0..2] of TSymmetricSpec = (
    (Algorithm: 'SALSA20'; DisplayName: 'Salsa20'; KeyByteCount: 32; IvByteCount: 8),
    (Algorithm: 'CHACHA20'; DisplayName: 'ChaCha20'; KeyByteCount: 32; IvByteCount: 12),
    (Algorithm: 'XCHACHA20'; DisplayName: 'XChaCha20'; KeyByteCount: 32; IvByteCount: 24)
  );

procedure TStreamCipherExample.Run;
begin
  RunSpecs('--- Stream cipher example: encrypt/decrypt ---', StreamSpecs);
end;

end.
