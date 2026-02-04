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

unit ClpEd25519PrivateKeyParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpEd25519,
  ClpISecureRandom,
  ClpAsymmetricKeyParameter,
  ClpIEd25519PrivateKeyParameters,
  ClpIEd25519PublicKeyParameters,
  ClpEd25519PublicKeyParameters,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SEOFInPrivateKey = 'EOF encountered in middle of Ed25519 private key';
  SUnsupportedAlgorithm = 'Unsupported Algorithm';
  SCtxNotNil = 'Ctx must be Nil for Ed25519 Algorithm';
  SCtxNil = 'Ctx must not be Nil for Ed25519ctx/Ed25519ph';
  SCtxLength = 'Ctx length must be at most 255';
  SMsgLen = 'MsgLen must be Equal to PreHashSize for Ed25519ph Algorithm';
  SMustHaveLengthKeySize = 'must have length %d';

type
  TEd25519PrivateKeyParameters = class sealed(TAsymmetricKeyParameter,
    IEd25519PrivateKeyParameters)

  strict private
  var
    FData: TCryptoLibByteArray;
    FCachedPublicKey: IEd25519PublicKeyParameters;

  public

    const
    KeySize = Int32(TEd25519.SecretKeySize);
    SignatureSize = Int32(TEd25519.SignatureSize);

    constructor Create(const ARandom: ISecureRandom); overload;
    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    constructor Create(AInput: TStream); overload;

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;
    function GeneratePublicKey(): IEd25519PublicKeyParameters;

    procedure Sign(AAlgorithm: TEd25519.TAlgorithm;
      const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32);

    function Equals(const AOther: IEd25519PrivateKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

implementation

{ TEd25519PrivateKeyParameters }

function TEd25519PrivateKeyParameters.GeneratePublicKey
  : IEd25519PublicKeyParameters;
var
  LPoint: TEd25519.IPublicPoint;
begin
  if FCachedPublicKey = nil then
  begin
    LPoint := TEd25519.GeneratePublicKey(FData, 0);
    FCachedPublicKey := TEd25519PublicKeyParameters.Create(LPoint);
  end;
  Result := FCachedPublicKey;
end;

function TEd25519PrivateKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  Result := System.Copy(FData);
end;

constructor TEd25519PrivateKeyParameters.Create(const ARandom: ISecureRandom);
var
  LEd25519: TEd25519;
begin
  Inherited Create(True);
  System.SetLength(FData, KeySize);
  LEd25519 := TEd25519.Create();
  try
    LEd25519.GeneratePrivateKey(ARandom, FData);
  finally
    LEd25519.Free;
  end;
end;

constructor TEd25519PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  if System.Length(ABuf) <> KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [KeySize]);
  Create(ABuf, 0);
end;

constructor TEd25519PrivateKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  Inherited Create(True);
  System.SetLength(FData, KeySize);
  System.Move(ABuf[AOff], FData[0], KeySize * System.SizeOf(Byte));
end;

constructor TEd25519PrivateKeyParameters.Create(AInput: TStream);
begin
  Inherited Create(True);
  System.SetLength(FData, KeySize);
  if KeySize <> TStreamUtilities.ReadFully(AInput, FData) then
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPrivateKey);
end;

procedure TEd25519PrivateKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  System.Move(FData[0], ABuf[AOff], KeySize * System.SizeOf(Byte));
end;

function TEd25519PrivateKeyParameters.Equals(const AOther
  : IEd25519PrivateKeyParameters): Boolean;
begin
  if (AOther = Self as IEd25519PrivateKeyParameters) then
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

function TEd25519PrivateKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(FData);
end;

procedure TEd25519PrivateKeyParameters.Sign(AAlgorithm: TEd25519.TAlgorithm;
  const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LPublicKey: IEd25519PublicKeyParameters;
  LPk: TCryptoLibByteArray;
  LEd25519: TEd25519;
begin
  LPublicKey := GeneratePublicKey();
  System.SetLength(LPk, TEd25519.PublicKeySize);
  LPublicKey.Encode(LPk, 0);

  LEd25519 := TEd25519.Create();
  try
    case AAlgorithm of
      TEd25519.TAlgorithm.Ed25519:
        begin
          if ACtx <> nil then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SCtxNotNil);
          LEd25519.Sign(FData, 0, LPk, 0, AMsg, AMsgOff, AMsgLen, ASig, ASigOff);
        end;

      TEd25519.TAlgorithm.Ed25519ctx:
        begin
          // Note: In Pascal, nil and empty arrays are equivalent.
          // We allow nil here, treating it as an empty context.
          if System.Length(ACtx) > 255 then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SCtxLength);
          LEd25519.Sign(FData, 0, LPk, 0, ACtx, AMsg, AMsgOff, AMsgLen, ASig,
            ASigOff);
        end;

      TEd25519.TAlgorithm.Ed25519ph:
        begin
          // Note: In Pascal, nil and empty arrays are equivalent.
          // We allow nil here, treating it as an empty context.
          if System.Length(ACtx) > 255 then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SCtxLength);
          if TEd25519.PrehashSize <> AMsgLen then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SMsgLen);
          LEd25519.SignPrehash(FData, 0, LPk, 0, ACtx, AMsg, AMsgOff, ASig,
            ASigOff);
        end
    else
      raise EInvalidOperationCryptoLibException.CreateRes(@SUnsupportedAlgorithm);
    end;
  finally
    LEd25519.Free;
  end;
end;

end.
