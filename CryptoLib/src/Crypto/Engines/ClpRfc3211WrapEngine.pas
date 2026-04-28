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

unit ClpRfc3211WrapEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIRfc3211WrapEngine,
  ClpIWrapper,
  ClpIBlockCipher,
  ClpICbcBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpISecureRandom,
  ClpCbcBlockCipher,
  ClpParametersWithIV,
  ClpParameterUtilities,
  ClpCryptoServicesRegistrar,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SNotSetForWrapping3211 = 'Not set for wrapping';
  SNotSetForUnwrapping3211 = 'Not set for unwrapping';
  SRFC3211WrapRequiresIV = 'RFC3211Wrap requires an IV';
  SInputTooLarge = 'Input must be from 0 to 255 bytes';
  SInputTooShort3211 = 'Input too short';
  SWrappedKeyCorrupted = 'Wrapped key corrupted';

type
  /// <summary>
  /// An implementation of the RFC 3211 Key Wrap Specification.
  /// </summary>
  TRfc3211WrapEngine = class(TInterfacedObject, IRfc3211WrapEngine, IWrapper)

  strict private
  var
    FEngine: ICbcBlockCipher;
    FParam: IParametersWithIV;
    FForWrapping: Boolean;
    FRand: ISecureRandom;

    function GetAlgorithmName: String; virtual;

  public
    constructor Create(const AEngine: IBlockCipher);

    procedure Init(AForWrapping: Boolean; const AParam: ICipherParameters); virtual;

    function Wrap(const AInBytes: TCryptoLibByteArray; AInOff, AInLen: Int32): TCryptoLibByteArray; virtual;

    function Unwrap(const AInBytes: TCryptoLibByteArray; AInOff, AInLen: Int32): TCryptoLibByteArray; virtual;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TRfc3211WrapEngine }

constructor TRfc3211WrapEngine.Create(const AEngine: IBlockCipher);
begin
  inherited Create;
  FEngine := TCbcBlockCipher.Create(AEngine);
end;

function TRfc3211WrapEngine.GetAlgorithmName: String;
begin
  Result := FEngine.GetUnderlyingCipher().AlgorithmName + '/RFC3211Wrap';
end;

procedure TRfc3211WrapEngine.Init(AForWrapping: Boolean;
  const AParam: ICipherParameters);
var
  LStrippedParams: ICipherParameters;
  LProvidedRandom: ISecureRandom;
  LWithIV: IParametersWithIV;
begin
  FForWrapping := AForWrapping;

  LStrippedParams := TParameterUtilities.GetRandom(AParam, LProvidedRandom);

  if not Supports(LStrippedParams, IParametersWithIV, LWithIV) then
    raise EArgumentCryptoLibException.CreateRes(@SRFC3211WrapRequiresIV);

  FParam := LWithIV;

  if FForWrapping then
    FRand := TCryptoServicesRegistrar.GetSecureRandom(LProvidedRandom)
  else
    FRand := nil;
end;

function TRfc3211WrapEngine.Wrap(const AInBytes: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LBlockSize, LI: Int32;
  LCekBlock: TCryptoLibByteArray;
begin
  if not FForWrapping then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotSetForWrapping3211);
  if (AInLen > 255) or (AInLen < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SInputTooLarge);

  FEngine.Init(True, FParam);

  LBlockSize := FEngine.GetBlockSize();

  if AInLen + 4 < LBlockSize * 2 then
    System.SetLength(LCekBlock, LBlockSize * 2)
  else
  begin
    if (AInLen + 4) mod LBlockSize = 0 then
      System.SetLength(LCekBlock, AInLen + 4)
    else
      System.SetLength(LCekBlock, ((AInLen + 4) div LBlockSize + 1) * LBlockSize);
  end;

  LCekBlock[0] := Byte(AInLen);

  System.Move(AInBytes[AInOff], LCekBlock[4], AInLen * System.SizeOf(Byte));

  FRand.NextBytes(LCekBlock, AInLen + 4, System.Length(LCekBlock) - AInLen - 4);

  LCekBlock[1] := not LCekBlock[4];
  LCekBlock[2] := not LCekBlock[4 + 1];
  LCekBlock[3] := not LCekBlock[4 + 2];

  LI := 0;
  while LI < System.Length(LCekBlock) do
  begin
    FEngine.ProcessBlock(LCekBlock, LI, LCekBlock, LI);
    Inc(LI, LBlockSize);
  end;

  LI := 0;
  while LI < System.Length(LCekBlock) do
  begin
    FEngine.ProcessBlock(LCekBlock, LI, LCekBlock, LI);
    Inc(LI, LBlockSize);
  end;

  Result := LCekBlock;
end;

function TRfc3211WrapEngine.Unwrap(const AInBytes: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LBlockSize, LI, LNonEqual: Int32;
  LInvalidLength: Boolean;
  LCekBlock, LIv, LKey: TCryptoLibByteArray;
  LCheck: Byte;
begin
  if FForWrapping then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotSetForUnwrapping3211);

  LBlockSize := FEngine.GetBlockSize();

  if AInLen < 2 * LBlockSize then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SInputTooShort3211);

  System.SetLength(LCekBlock, AInLen);
  System.SetLength(LIv, LBlockSize);

  System.Move(AInBytes[AInOff], LCekBlock[0], AInLen * System.SizeOf(Byte));
  System.Move(AInBytes[AInOff], LIv[0], System.Length(LIv) * System.SizeOf(Byte));

  FEngine.Init(False, TParametersWithIV.Create(FParam.Parameters, LIv) as IParametersWithIV);

  LI := LBlockSize;
  while LI < System.Length(LCekBlock) do
  begin
    FEngine.ProcessBlock(LCekBlock, LI, LCekBlock, LI);
    Inc(LI, LBlockSize);
  end;

  System.Move(LCekBlock[System.Length(LCekBlock) - System.Length(LIv)], LIv[0],
    System.Length(LIv) * System.SizeOf(Byte));

  FEngine.Init(False, TParametersWithIV.Create(FParam.Parameters, LIv) as IParametersWithIV);

  FEngine.ProcessBlock(LCekBlock, 0, LCekBlock, 0);

  FEngine.Init(False, FParam);

  LI := 0;
  while LI < System.Length(LCekBlock) do
  begin
    FEngine.ProcessBlock(LCekBlock, LI, LCekBlock, LI);
    Inc(LI, LBlockSize);
  end;

  LInvalidLength := Int32(LCekBlock[0]) > (System.Length(LCekBlock) - 4);

  if LInvalidLength then
    System.SetLength(LKey, System.Length(LCekBlock) - 4)
  else
    System.SetLength(LKey, LCekBlock[0]);

  System.Move(LCekBlock[4], LKey[0], System.Length(LKey) * System.SizeOf(Byte));

  LNonEqual := 0;
  for LI := 0 to 2 do
  begin
    LCheck := Byte(not LCekBlock[1 + LI]);
    LNonEqual := LNonEqual or (LCheck xor LCekBlock[4 + LI]);
  end;

  TArrayUtilities.Fill<Byte>(LCekBlock, 0, System.Length(LCekBlock), Byte(0));

  if (LNonEqual <> 0) or LInvalidLength then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SWrappedKeyCorrupted);

  Result := LKey;
end;

end.
