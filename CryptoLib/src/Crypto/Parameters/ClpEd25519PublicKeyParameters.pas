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

unit ClpEd25519PublicKeyParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpEd25519,
  ClpAsymmetricKeyParameter,
  ClpIEd25519PublicKeyParameters,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SEOFInPublicKey = 'EOF encountered in middle of Ed25519 public key';
  SInvalidPublicKey = 'invalid public key';
  SMustHaveLengthKeySize = 'must have length %d';

type
  TEd25519PublicKeyParameters = class sealed(TAsymmetricKeyParameter,
    IEd25519PublicKeyParameters)

  strict private
  var
    FPublicPoint: TEd25519.IPublicPoint;

  public

    const
    KeySize = Int32(TEd25519.PublicKeySize);

    constructor Create(const ABuf: TCryptoLibByteArray); overload;
    constructor Create(const ABuf: TCryptoLibByteArray; AOff: Int32); overload;
    constructor Create(AInput: TStream); overload;
    constructor Create(const APublicPoint: TEd25519.IPublicPoint); overload;

    procedure Encode(const ABuf: TCryptoLibByteArray; AOff: Int32); inline;
    function GetEncoded(): TCryptoLibByteArray; inline;

    function Verify(AAlgorithm: TEd25519.TAlgorithm;
      const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32): Boolean;

    function Equals(const AOther: IEd25519PublicKeyParameters): Boolean;
      reintroduce; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

  end;

implementation

{ TEd25519PublicKeyParameters }

constructor TEd25519PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray);
begin
  if System.Length(ABuf) <> KeySize then
    raise EArgumentCryptoLibException.CreateResFmt(@SMustHaveLengthKeySize,
      [KeySize]);
  Create(ABuf, 0);
end;

constructor TEd25519PublicKeyParameters.Create(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
var
  LPoint: TEd25519.IPublicPoint;
begin
  Inherited Create(False);
  LPoint := TEd25519.ValidatePublicKeyPartialExport(ABuf, AOff);
  if LPoint = nil then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPublicKey);
  FPublicPoint := LPoint;
end;

constructor TEd25519PublicKeyParameters.Create(AInput: TStream);
var
  LData: TCryptoLibByteArray;
  LPoint: TEd25519.IPublicPoint;
begin
  Inherited Create(False);
  System.SetLength(LData, KeySize);
  if KeySize <> TStreamUtilities.ReadFully(AInput, LData) then
    raise EEndOfStreamCryptoLibException.CreateRes(@SEOFInPublicKey);
  LPoint := TEd25519.ValidatePublicKeyPartialExport(LData, 0);
  if LPoint = nil then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPublicKey);
  FPublicPoint := LPoint;
end;

constructor TEd25519PublicKeyParameters.Create(const APublicPoint
  : TEd25519.IPublicPoint);
begin
  Inherited Create(False);
  if APublicPoint = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SInvalidPublicKey);
  FPublicPoint := APublicPoint;
end;

procedure TEd25519PublicKeyParameters.Encode(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
begin
  TEd25519.EncodePublicPoint(FPublicPoint, ABuf, AOff);
end;

function TEd25519PublicKeyParameters.GetEncoded: TCryptoLibByteArray;
begin
  System.SetLength(Result, KeySize);
  Encode(Result, 0);
end;

function TEd25519PublicKeyParameters.Verify(AAlgorithm: TEd25519.TAlgorithm;
  const ACtx, AMsg: TCryptoLibByteArray; AMsgOff, AMsgLen: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32): Boolean;
var
  LEd25519: TEd25519;
begin
  LEd25519 := TEd25519.Create();
  try
    case AAlgorithm of
      TEd25519.TAlgorithm.Ed25519:
        begin
          if ACtx <> nil then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidPublicKey);
          Result := LEd25519.Verify(ASig, ASigOff, FPublicPoint, AMsg, AMsgOff,
            AMsgLen);
        end;
      TEd25519.TAlgorithm.Ed25519ctx:
        begin
          // Note: In Pascal, nil and empty arrays are equivalent.
          // We allow nil here, treating it as an empty context.
          if System.Length(ACtx) > 255 then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes
              (@SInvalidPublicKey);
          Result := LEd25519.Verify(ASig, ASigOff, FPublicPoint, ACtx, AMsg,
            AMsgOff, AMsgLen);
        end;
      TEd25519.TAlgorithm.Ed25519ph:
        begin
          // Note: In Pascal, nil and empty arrays are equivalent.
          // We allow nil here, treating it as an empty context.
          if System.Length(ACtx) > 255 then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes
              (@SInvalidPublicKey);
          if TEd25519.PrehashSize <> AMsgLen then
            raise EArgumentOutOfRangeCryptoLibException.CreateRes
              (@SInvalidPublicKey);
          Result := LEd25519.VerifyPreHash(ASig, ASigOff, FPublicPoint, ACtx,
            AMsg, AMsgOff);
        end
    else
      raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidPublicKey);
    end;
  finally
    LEd25519.Free;
  end;
end;

function TEd25519PublicKeyParameters.Equals(const AOther
  : IEd25519PublicKeyParameters): Boolean;
var
  LEncoded, LOtherEncoded: TCryptoLibByteArray;
begin
  if (AOther = Self as IEd25519PublicKeyParameters) then
  begin
    Result := True;
    Exit;
  end;

  if (AOther = nil) then
  begin
    Result := False;
    Exit;
  end;
  LEncoded := GetEncoded();
  LOtherEncoded := AOther.GetEncoded();
  Result := TArrayUtilities.FixedTimeEquals(LEncoded, LOtherEncoded);
end;

function TEd25519PublicKeyParameters.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  Result := TArrayUtilities.GetArrayHashCode(GetEncoded());
end;

end.
