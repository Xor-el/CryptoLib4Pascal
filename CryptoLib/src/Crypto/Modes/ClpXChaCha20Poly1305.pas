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

unit ClpXChaCha20Poly1305;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIXChaCha20Poly1305,
  ClpChaCha20Poly1305,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpIMac,
  ClpKeyParameter,
  ClpAeadParameters,
  ClpParametersWithIV,
  ClpCipherModeParameterUtilities,
  ClpChaChaEngine,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInvalidParameters = 'invalid parameters passed to XChaCha20Poly1305';
  SNonceMustBe192 = 'XChaCha20Poly1305 requires a 192 bit nonce';
  SInvalidMacSize = 'Invalid value for MAC size: %d';
  SKeyMustBe256 = 'Key must be 256 bits';
  SKeyMustBeSpecified = 'Key must be specified in initial init';

type
  TXChaCha20Poly1305 = class(TChaCha20Poly1305, IXChaCha20Poly1305, IAeadCipher)

  strict private
    FMasterKey: TCryptoLibByteArray;

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(); overload;
    constructor Create(const APoly1305: IMac); overload;
    destructor Destroy; override;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); override;
  end;

implementation

{ TXChaCha20Poly1305 }

constructor TXChaCha20Poly1305.Create;
begin
  inherited Create();
  System.SetLength(FMasterKey, KeySize);
end;

constructor TXChaCha20Poly1305.Create(const APoly1305: IMac);
begin
  inherited Create(APoly1305);
  System.SetLength(FMasterKey, KeySize);
end;

destructor TXChaCha20Poly1305.Destroy;
begin
  TArrayUtilities.Fill<Byte>(FMasterKey, 0, System.Length(FMasterKey), Byte(0));
  inherited Destroy;
end;

function TXChaCha20Poly1305.GetAlgorithmName: String;
begin
  Result := 'XChaCha20Poly1305';
end;

procedure TXChaCha20Poly1305.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LChoice: TCipherAeadChoice;
  LInitKeyParam: IKeyParameter;
  LOuterNonce: TCryptoLibByteArray;
  LMacSizeBits: Int32;
  LSubKey: TCryptoLibByteArray;
  LInnerIv: TCryptoLibByteArray;
  LNoncePrefix: TCryptoLibByteArray;
  LInnerParams: ICipherParameters;
  LInnerKey: IKeyParameter;
begin
  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameters);

  LInitKeyParam := LChoice.KeyParameter;
  LOuterNonce := LChoice.Nonce;

  if (LOuterNonce = nil) or (System.Length(LOuterNonce) <> 24) then
    raise EArgumentCryptoLibException.CreateRes(@SNonceMustBe192);

  if LChoice.IsAead then
  begin
    LMacSizeBits := LChoice.MacSizeBits;
    if ((MacSize * 8) <> LMacSizeBits) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMacSize,
        [LMacSizeBits]);
  end;

  if (LInitKeyParam = nil) then
  begin
    if (TState.Uninitialized = FState) then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
  end
  else
  begin
    if (KeySize <> LInitKeyParam.KeyLength) then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBe256);
    LInitKeyParam.CopyKeyTo(FMasterKey, 0, KeySize);
  end;

  LNoncePrefix := Copy(LOuterNonce, 0, 16);
  System.SetLength(LSubKey, 32);
  try
    TChaChaEngine.HChaCha20(FMasterKey, LNoncePrefix, LSubKey, 0);
  finally
    TArrayUtilities.Fill<Byte>(LNoncePrefix, 0, System.Length(LNoncePrefix),
      Byte(0));
  end;

  System.SetLength(LInnerIv, 12);
  System.FillChar(LInnerIv[0], 4, 0);
  System.Move(LOuterNonce[16], LInnerIv[4], 8);

  try
    LInnerKey := TKeyParameter.Create(LSubKey);
  finally
    TArrayUtilities.Fill<Byte>(LSubKey, 0, 32, Byte(0));
  end;

  if LChoice.IsAead then
    LInnerParams := TAeadParameters.Create(LInnerKey, LMacSizeBits, LInnerIv,
      LChoice.AssociatedText)
  else
    LInnerParams := TParametersWithIV.Create(LInnerKey, LInnerIv);

  inherited Init(AForEncryption, LInnerParams);
end;

end.
