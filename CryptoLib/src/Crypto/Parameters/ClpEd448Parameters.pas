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

unit ClpEd448Parameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpEd448,
  ClpISecureRandom,
  ClpAsymmetricKeyParameter,
  ClpIEd448Parameters,
  ClpKeyGenerationParameters,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SEOFInPublicKey = 'EOF encountered in middle of Ed448 public key';
  SInvalidPublicKey = 'invalid public key';
  SMustHaveLengthKeySize = 'must have length %d';
  SEOFInPrivateKey = 'EOF encountered in middle of Ed448 private key';
  SUnsupportedAlgorithm = 'Unsupported Algorithm';
  SCtxNil = 'Ctx must not be Nil for Ed448/Ed448ph';
  SCtxLength = 'Ctx length must be at most 255';
  SMsgLen = 'MsgLen must be Equal to PreHashSize for Ed448ph Algorithm';

type
  TEd448PublicKeyParameters = class sealed(TAsymmetricKeyParameter,
    IEd448PublicKeyParameters)

  strict private
  var
    FPublicPoint: TEd448.IPublicPoint;

  public
    const
    KeySize = Int32(57);

    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    constructor Create(AInput: TStream); overload;
    constructor Create(const APublicPoint: TEd448.IPublicPoint); overload;

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;

    function Verify(AAlgorithm: TEd448.TAlgorithm;
      const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32): Boolean;

    function Equals(const AOther: IEd448PublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  TEd448PrivateKeyParameters = class sealed(TAsymmetricKeyParameter,
    IEd448PrivateKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;
    FCachedPublicKey: IEd448PublicKeyParameters;

  public
    const
    KeySize = Int32(57);
    SignatureSize = Int32(57 + 57);

    constructor Create(const ARandom: ISecureRandom); overload;
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    constructor Create(AInput: TStream); overload;

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;
    function GeneratePublicKey(): IEd448PublicKeyParameters;

    procedure Sign(AAlgorithm: TEd448.TAlgorithm;
      const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32);

    function Equals(const AOther: IEd448PrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;
  end;

  TEd448KeyGenerationParameters = class sealed(TKeyGenerationParameters,
    IEd448KeyGenerationParameters)

  public
    constructor Create(const ARandom: ISecureRandom);
  end;

implementation

{ TEd448PublicKeyParameters }

constructor TEd448PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  if System.Length(ABuf) <> KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [KeySize]);
  Create(ABuf, 0);
end;

constructor TEd448PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  inherited Create(False);
  FPublicPoint := TEd448.ValidatePublicKeyPartialExport(ABuf, AOff);
  if FPublicPoint = nil then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPublicKey);
end;

constructor TEd448PublicKeyParameters.Create(AInput: TStream);
var
  LBuf: TCryptoLibByteArray;
begin
  inherited Create(False);
  System.SetLength(LBuf, KeySize);
  if (KeySize <> TStreamUtilities.ReadFully(AInput, LBuf)) then
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPublicKey);
  FPublicPoint := TEd448.ValidatePublicKeyPartialExport(LBuf, 0);
  if FPublicPoint = nil then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPublicKey);
end;

constructor TEd448PublicKeyParameters.Create(const APublicPoint: TEd448.IPublicPoint);
begin
  inherited Create(False);
  if APublicPoint = nil then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPublicKey);
  FPublicPoint := APublicPoint;
end;

procedure TEd448PublicKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  TEd448.EncodePublicPoint(FPublicPoint, ABuf, AOff);
end;

function TEd448PublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  System.SetLength(Result, KeySize);
  Encode(Result, 0);
end;

function TEd448PublicKeyParameters.Verify(AAlgorithm: TEd448.TAlgorithm;
  const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32): Boolean;
var
  LEd448: TEd448;
begin
  LEd448 := TEd448.Create();
  try
    case AAlgorithm of
      TEd448.TAlgorithm.Ed448:
        begin
          if System.Length(ACtx) > 255 then
            raise EArgumentCryptoLibException.CreateRes(@SCtxLength);
          Result := LEd448.Verify(ASig, ASigOff, FPublicPoint, ACtx, AMsg,
            AMsgOff, AMsgLen);
        end;
      TEd448.TAlgorithm.Ed448ph:
        begin
          if System.Length(ACtx) > 255 then
            raise EArgumentCryptoLibException.CreateRes(@SCtxLength);
          if AMsgLen <> TEd448.PrehashSize then
            raise EArgumentCryptoLibException.CreateRes(@SMsgLen);
          Result := LEd448.VerifyPrehash(ASig, ASigOff, FPublicPoint, ACtx, AMsg, AMsgOff);
        end;
    else
      raise EArgumentCryptoLibException.CreateRes(@SUnsupportedAlgorithm);
    end;
  finally
    LEd448.Free;
  end;
end;

function TEd448PublicKeyParameters.Equals(const AOther: IEd448PublicKeyParameters): Boolean;
var
  LThis, LOther: TCryptoLibByteArray;
begin
  if (AOther = Self as IEd448PublicKeyParameters) then
  begin
    Result := True;
    Exit;
  end;

  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;
  LThis := GetEncoded();
  LOther := AOther.GetEncoded();
  Result := TArrayUtilities.FixedTimeEquals(LThis, LOther);
end;

function TEd448PublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(GetEncoded());
end;

{ TEd448PrivateKeyParameters }

constructor TEd448PrivateKeyParameters.Create(const ARandom: ISecureRandom);
var
  LEd448: TEd448;
begin
  inherited Create(True);
  System.SetLength(FData, KeySize);
  LEd448 := TEd448.Create();
  try
    LEd448.GeneratePrivateKey(ARandom, FData);
  finally
    LEd448.Free;
  end;
end;

constructor TEd448PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  if System.Length(ABuf) <> KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize, [KeySize]);
  Create(ABuf, 0);
end;

constructor TEd448PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  inherited Create(True);
  System.SetLength(FData, KeySize);
  System.Move(ABuf[AOff], FData[0], KeySize * System.SizeOf(Byte));
end;

constructor TEd448PrivateKeyParameters.Create(AInput: TStream);
begin
  inherited Create(True);
  System.SetLength(FData, KeySize);
  if (KeySize <> TStreamUtilities.ReadFully(AInput, FData)) then
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPrivateKey);
end;

procedure TEd448PrivateKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  System.Move(FData[0], ABuf[AOff], KeySize * System.SizeOf(Byte));
end;

function TEd448PrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FData);
end;

function TEd448PrivateKeyParameters.GeneratePublicKey: IEd448PublicKeyParameters;
var
  LEd448: TEd448;
  LPublicPoint: TEd448.IPublicPoint;
begin
  if FCachedPublicKey = nil then
  begin
    LEd448 := TEd448.Create();
    try
      LPublicPoint := LEd448.GeneratePublicKey(FData, 0);
      FCachedPublicKey := TEd448PublicKeyParameters.Create(LPublicPoint);
    finally
      LEd448.Free;
    end;
  end;
  Result := FCachedPublicKey;
end;

procedure TEd448PrivateKeyParameters.Sign(AAlgorithm: TEd448.TAlgorithm;
  const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LEd448: TEd448;
  LPk: TCryptoLibByteArray;
begin
  LPk := GeneratePublicKey().GetEncoded();
  LEd448 := TEd448.Create();
  try
    case AAlgorithm of
      TEd448.TAlgorithm.Ed448:
        begin
          if System.Length(ACtx) > 255 then
            raise EArgumentCryptoLibException.CreateRes(@SCtxLength);
          LEd448.Sign(FData, 0, LPk, 0, ACtx, AMsg, AMsgOff, AMsgLen, ASig, ASigOff);
        end;
      TEd448.TAlgorithm.Ed448ph:
        begin
          if System.Length(ACtx) > 255 then
            raise EArgumentCryptoLibException.CreateRes(@SCtxLength);
          if AMsgLen <> TEd448.PrehashSize then
            raise EArgumentCryptoLibException.CreateRes(@SMsgLen);
          LEd448.SignPrehash(FData, 0, LPk, 0, ACtx, AMsg, AMsgOff, ASig, ASigOff);
        end;
    else
      raise EArgumentCryptoLibException.CreateRes(@SUnsupportedAlgorithm);
    end;
  finally
    LEd448.Free;
  end;
end;

function TEd448PrivateKeyParameters.Equals(const AOther: IEd448PrivateKeyParameters): Boolean;
begin
  if (AOther = Self as IEd448PrivateKeyParameters) then
  begin
    Result := True;
    Exit;
  end;

  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.FixedTimeEquals(FData, AOther.GetEncoded());
end;

function TEd448PrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(FData);
end;

{ TEd448KeyGenerationParameters }

constructor TEd448KeyGenerationParameters.Create(const ARandom: ISecureRandom);
begin
  inherited Create(ARandom, 448);
end;

end.
