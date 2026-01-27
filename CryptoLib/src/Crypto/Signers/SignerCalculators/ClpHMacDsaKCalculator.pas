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

unit ClpHMacDsaKCalculator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  ClpHMac,
  ClpIHMac,
  ClpIDigest,
  ClpISecureRandom,
  ClpBigInteger,
  ClpBigIntegers,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpIDsaKCalculator,
  ClpIHMacDsaKCalculator,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

{$IFNDEF _FIXINSIGHT_}

resourcestring
  SUnSupportedOperation = 'Operation not Supported';
{$ENDIF}

type

  /// <summary>
  /// A deterministic K calculator based on the algorithm in section 3.2 of
  /// RFC 6979.
  /// </summary>
  THMacDsaKCalculator = class(TInterfacedObject, IDsaKCalculator,
    IHMacDsaKCalculator)

  strict private
  var
    FHmac: IHMac;
    FK, FV: TCryptoLibByteArray;
    FN: TBigInteger;

    function BitsToInt(const AT: TCryptoLibByteArray): TBigInteger; inline;

    function GetIsDeterministic: Boolean; virtual;

  public

    /// <summary>
    /// Base constructor.
    /// </summary>
    /// <param name="digest">
    /// digest to build the HMAC on.
    /// </param>
    constructor Create(const ADigest: IDigest);

    procedure Init(const AN: TBigInteger; const ARandom: ISecureRandom);
      overload; virtual;

    procedure Init(const AN, AD: TBigInteger;
      const AMessage: TCryptoLibByteArray); overload;

    function NextK(): TBigInteger; virtual;

    property IsDeterministic: Boolean read GetIsDeterministic;

  end;

implementation

{ THMacDsaKCalculator }

function THMacDsaKCalculator.GetIsDeterministic: Boolean;
begin
  Result := True;
end;

function THMacDsaKCalculator.BitsToInt(const AT: TCryptoLibByteArray)
  : TBigInteger;
begin
  Result := TBigInteger.Create(1, AT);
  if ((System.Length(AT) * 8) > FN.BitLength) then
  begin
    Result := Result.ShiftRight((System.Length(AT) * 8) - FN.BitLength);
  end;
end;

constructor THMacDsaKCalculator.Create(const ADigest: IDigest);
begin
  Inherited Create();
  FHmac := THMac.Create(ADigest);
  System.SetLength(FV, FHmac.GetMacSize());
  System.SetLength(FK, FHmac.GetMacSize());
end;

{$IFNDEF _FIXINSIGHT_}

procedure THMacDsaKCalculator.Init(const AN: TBigInteger;
  const ARandom: ISecureRandom);
begin
  raise EInvalidOperationCryptoLibException.CreateRes(@SUnSupportedOperation);
end;
{$ENDIF}

procedure THMacDsaKCalculator.Init(const AN, AD: TBigInteger;
  const AMessage: TCryptoLibByteArray);
var
  LX, LDVal, LM, LMVal: TCryptoLibByteArray;
  LMInt: TBigInteger;
  LSize: Int32;
begin
  FN := AN;
  TArrayUtilities.Fill<Byte>(FV, 0, System.Length(FV), Byte($01));
  TArrayUtilities.Fill<Byte>(FK, 0, System.Length(FK), Byte(0));

  LSize := TBigIntegers.GetUnsignedByteLength(AN);
  System.SetLength(LX, LSize);

  LDVal := TBigIntegers.AsUnsignedByteArray(AD);

  System.Move(LDVal[0], LX[System.Length(LX) - System.Length(LDVal)],
    System.Length(LDVal));

  System.SetLength(LM, LSize);

  LMInt := BitsToInt(AMessage);

  if (LMInt.CompareTo(AN) >= 0) then
  begin
    LMInt := LMInt.Subtract(AN);
  end;

  LMVal := TBigIntegers.AsUnsignedByteArray(LMInt);

  System.Move(LMVal[0], LM[System.Length(LM) - System.Length(LMVal)],
    System.Length(LMVal));

  FHmac.Init(TKeyParameter.Create(FK) as IKeyParameter);

  FHmac.BlockUpdate(FV, 0, System.Length(FV));
  FHmac.Update(Byte($00));
  FHmac.BlockUpdate(LX, 0, System.Length(LX));
  FHmac.BlockUpdate(LM, 0, System.Length(LM));

  FHmac.DoFinal(FK, 0);

  FHmac.Init(TKeyParameter.Create(FK) as IKeyParameter);

  FHmac.BlockUpdate(FV, 0, System.Length(FV));

  FHmac.DoFinal(FV, 0);

  FHmac.BlockUpdate(FV, 0, System.Length(FV));
  FHmac.Update(Byte($01));
  FHmac.BlockUpdate(LX, 0, System.Length(LX));
  FHmac.BlockUpdate(LM, 0, System.Length(LM));

  FHmac.DoFinal(FK, 0);

  FHmac.Init(TKeyParameter.Create(FK) as IKeyParameter);

  FHmac.BlockUpdate(FV, 0, System.Length(FV));

  FHmac.DoFinal(FV, 0);
end;

function THMacDsaKCalculator.NextK: TBigInteger;
var
  LT: TCryptoLibByteArray;
  LTOff, LLength: Int32;
begin
  Result := Default (TBigInteger);
  System.SetLength(LT, TBigIntegers.GetUnsignedByteLength(FN));

  while True do

  begin
    LTOff := 0;

    while (LTOff < System.Length(LT)) do
    begin
      FHmac.BlockUpdate(FV, 0, System.Length(FV));

      FHmac.DoFinal(FV, 0);

      LLength := Min(System.Length(LT) - LTOff, System.Length(FV));
      System.Move(FV[0], LT[LTOff], LLength * System.SizeOf(Byte));
      LTOff := LTOff + LLength;
    end;

    Result := BitsToInt(LT);

    if ((Result.SignValue > 0) and (Result.CompareTo(FN) < 0)) then
    begin
      Exit;
    end;

    FHmac.BlockUpdate(FV, 0, System.Length(FV));
    FHmac.Update(Byte($00));

    FHmac.DoFinal(FK, 0);

    FHmac.Init(TKeyParameter.Create(FK) as IKeyParameter);

    FHmac.BlockUpdate(FV, 0, System.Length(FV));

    FHmac.DoFinal(FV, 0);
  end;
end;

end.
