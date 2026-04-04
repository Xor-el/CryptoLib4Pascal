{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCipherFactory;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Rtti,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpNistObjectIdentifiers,
  ClpICipherParameters,
  ClpIBlockCipherMode,
  ClpIBufferedCipher,
  ClpIBufferedBlockCipher,
  ClpIPaddedBufferedBlockCipher,
  ClpIPkcs7Padding,
  ClpAesEngine,
  ClpIAesEngine,
  ClpCbcBlockCipher,
  ClpPaddedBufferedBlockCipher,
  ClpPkcs7Padding,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Factory for creating content encryption ciphers.
  /// </summary>
  TCipherFactory = class sealed(TObject)
  strict private
    class function CreateCipher(const AAlgorithm: IDerObjectIdentifier): IBufferedBlockCipher; static;
  public
    /// <summary>
    /// Create a content cipher initialized with the given key and algorithm identifier.
    /// </summary>
    class function CreateContentCipher(AForEncryption: Boolean;
      const AEncKey: ICipherParameters;
      const AEncryptionAlgID: IAlgorithmIdentifier): TValue; static;
  end;

implementation

{ TCipherFactory }

class function TCipherFactory.CreateContentCipher(AForEncryption: Boolean;
  const AEncKey: ICipherParameters;
  const AEncryptionAlgID: IAlgorithmIdentifier): TValue;
var
  LEncAlg: IDerObjectIdentifier;
  LCipher: IBufferedBlockCipher;
  LSParams: IAsn1Object;
  LIv: TCryptoLibByteArray;
  LDerNull: IDerNull;
begin
  LEncAlg := AEncryptionAlgID.Algorithm;

  LCipher := CreateCipher(AEncryptionAlgID.Algorithm);
  LSParams := AEncryptionAlgID.Parameters.ToAsn1Object();

  if (LSParams <> nil) and (not Supports(LSParams, IDerNull, LDerNull)) then
  begin
    if LEncAlg.Equals(TNistObjectIdentifiers.IdAes128Cbc)
      or LEncAlg.Equals(TNistObjectIdentifiers.IdAes192Cbc)
      or LEncAlg.Equals(TNistObjectIdentifiers.IdAes256Cbc) then
    begin
      LIv := TAsn1OctetString.GetInstance(LSParams).GetOctets();
      LCipher.Init(AForEncryption, TParametersWithIV.Create(AEncKey, LIv) as IParametersWithIV);
    end
    else
    begin
      raise EInvalidOperationCryptoLibException.Create('cannot match parameters');
    end;
  end
  else
  begin
    LCipher.Init(AForEncryption, AEncKey);
  end;

  Result := TValue.From<IBufferedBlockCipher>(LCipher);
end;

class function TCipherFactory.CreateCipher(const AAlgorithm: IDerObjectIdentifier): IBufferedBlockCipher;
var
  LCipherMode: IBlockCipherMode;
begin
  if TNistObjectIdentifiers.IdAes128Cbc.Equals(AAlgorithm)
    or TNistObjectIdentifiers.IdAes192Cbc.Equals(AAlgorithm)
    or TNistObjectIdentifiers.IdAes256Cbc.Equals(AAlgorithm) then
  begin
    LCipherMode := TCbcBlockCipher.Create(TAesEngine.Create() as IAesEngine);
  end
  else
  begin
    raise EInvalidOperationCryptoLibException.Create('cannot recognise cipher: ' + AAlgorithm.Id);
  end;

  Result := TPaddedBufferedBlockCipher.Create(LCipherMode,
    TPkcs7Padding.Create() as IPkcs7Padding) as IPaddedBufferedBlockCipher;
end;

end.
