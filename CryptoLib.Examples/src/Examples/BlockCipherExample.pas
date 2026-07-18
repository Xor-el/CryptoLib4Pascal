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

unit BlockCipherExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  CipherExampleBase;

type
  TBlockCipherExample = class(TSymmetricCipherExampleBase)
  public
    procedure Run; override;
  end;

implementation

const
  // Add a block cipher/mode by adding a row. Arbitrary-length modes only
  // (so any plaintext works); each is driven through the shared non-AEAD
  // roundtrip.
  BlockSpecs: array[0..5] of TSymmetricSpec = (
    (Algorithm: 'AES/CBC/PKCS7PADDING'; DisplayName: 'AES-128-CBC'; KeyByteCount: 16; IvByteCount: 16),
    (Algorithm: 'AES/CBC/PKCS7PADDING'; DisplayName: 'AES-192-CBC'; KeyByteCount: 24; IvByteCount: 16),
    (Algorithm: 'AES/CBC/PKCS7PADDING'; DisplayName: 'AES-256-CBC'; KeyByteCount: 32; IvByteCount: 16),
    (Algorithm: 'AES/CTR/NOPADDING'; DisplayName: 'AES-256-CTR'; KeyByteCount: 32; IvByteCount: 16),
    (Algorithm: 'AES/CFB/NOPADDING'; DisplayName: 'AES-256-CFB'; KeyByteCount: 32; IvByteCount: 16),
    (Algorithm: 'BLOWFISH/CBC/PKCS7PADDING'; DisplayName: 'Blowfish-CBC'; KeyByteCount: 16; IvByteCount: 8)
  );

procedure TBlockCipherExample.Run;
begin
  RunSpecs('--- Block cipher example: encrypt/decrypt ---', BlockSpecs);
end;

end.
