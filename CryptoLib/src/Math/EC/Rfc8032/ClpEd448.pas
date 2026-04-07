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

unit ClpEd448;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  ClpDigestUtilities,
  ClpCodec,
  ClpBitOperations,
  ClpIXof,
  ClpISecureRandom,
  ClpNat,
  ClpScalar448,
  ClpWnaf,
  ClpX448Field,
  ClpCryptoLibTypes;

resourcestring
  SInvalidOp = 'Invalid point';
  SInvalidCtx = 'ctx';
  SInvalidPh = 'ph';

type
  TEd448 = class(TObject)
  strict private
  type
    TPointAffine = record
    private
      Fx, Fy: TCryptoLibUInt32Array;
    public
      property X: TCryptoLibUInt32Array read Fx write Fx;
      property Y: TCryptoLibUInt32Array read Fy write Fy;
    end;

    TPointProjective = record
    private
      Fx, Fy, Fz: TCryptoLibUInt32Array;
    public
      property X: TCryptoLibUInt32Array read Fx write Fx;
      property Y: TCryptoLibUInt32Array read Fy write Fy;
      property Z: TCryptoLibUInt32Array read Fz write Fz;
    end;

    TPointTemp = record
    private
      Fr0, Fr1, Fr2, Fr3, Fr4, Fr5, Fr6, Fr7: TCryptoLibUInt32Array;
    public
      property R0: TCryptoLibUInt32Array read Fr0 write Fr0;
      property R1: TCryptoLibUInt32Array read Fr1 write Fr1;
      property R2: TCryptoLibUInt32Array read Fr2 write Fr2;
      property R3: TCryptoLibUInt32Array read Fr3 write Fr3;
      property R4: TCryptoLibUInt32Array read Fr4 write Fr4;
      property R5: TCryptoLibUInt32Array read Fr5 write Fr5;
      property R6: TCryptoLibUInt32Array read Fr6 write Fr6;
      property R7: TCryptoLibUInt32Array read Fr7 write Fr7;
    end;

  public
   type
    TAlgorithm = (Ed448, Ed448ph);

    IPublicPoint = interface
      ['{A7B3C1D2-E4F5-6789-0ABC-DEF012345678}']
      function GetData: TCryptoLibUInt32Array;
      property Data: TCryptoLibUInt32Array read GetData;
    end;

    TPublicPoint = class sealed(TInterfacedObject, IPublicPoint)
    strict private
      FData: TCryptoLibUInt32Array;
      function GetData: TCryptoLibUInt32Array;
    public
      constructor Create(const AData: TCryptoLibUInt32Array);
      property Data: TCryptoLibUInt32Array read GetData;
    end;

  strict private
  const
    CoordUints = Int32(14);
    PointBytes = Int32(CoordUints * 4 + 1);
    ScalarUints = Int32(14);
    ScalarBytes = Int32(ScalarUints * 4 + 1);
    C_d = UInt32(39081);
    WnafWidth225 = Int32(5);
    WnafWidthBase = Int32(7);
    PrecompBlocks = Int32(5);
    PrecompTeeth = Int32(5);
    PrecompSpacing = Int32(18);
    PrecompRange = PrecompBlocks * PrecompTeeth * PrecompSpacing;
    PrecompPoints = 1 shl (PrecompTeeth - 1);
    PrecompMask = PrecompPoints - 1;
  class var
    FDom4Prefix: TCryptoLibByteArray;
    FP: TCryptoLibUInt32Array;
    FB_x, FB_y, FB225_x, FB225_y: TCryptoLibUInt32Array;
    FPrecompLock: TCriticalSection;
    FPrecompBaseWnaf: TCryptoLibGenericArray<TPointAffine>;
    FPrecompBase225Wnaf: TCryptoLibGenericArray<TPointAffine>;
    FPrecompBaseComb: TCryptoLibUInt32Array;
  class procedure Boot; static;
  class constructor Create;
  class destructor Destroy;
  class function CalculateS(const AR, AK, &AS: TCryptoLibByteArray): TCryptoLibByteArray; static;
  class function CheckContextVar(const ACtx: TCryptoLibByteArray): Boolean; static;
  class function CheckPoint(var AP: TPointAffine): Int32; overload; static;
  class function CheckPoint(const AP: TPointProjective): Int32; overload; static;
  class function CheckPointOrderVar(var AP: TPointAffine): Boolean; static;
  class function CheckPointFullVar(const AP: TCryptoLibByteArray): Boolean; static;
  class function CheckPointVar(const AP: TCryptoLibByteArray): Boolean; static;
  class function CopyBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): TCryptoLibByteArray; static;
  class function DecodePointVar(const AP: TCryptoLibByteArray; ANegate: Boolean; var AR: TPointAffine): Boolean; static;
  class procedure Dom4(const AD: IXof; APhflag: Byte; const ACtx: TCryptoLibByteArray); static;
  class procedure EncodePoint(var AP: TPointAffine; const AR: TCryptoLibByteArray; AROff: Int32); static;
  class function EncodeResult(var AP: TPointProjective; const AR: TCryptoLibByteArray; AROff: Int32): Int32; static;
  class function ExportPoint(var AP: TPointAffine): IPublicPoint; static;
  class function GetWindow4(const AX: TCryptoLibUInt32Array; AN: Int32): UInt32; static;
  function CreateAndValidateXof(): IXof;
  procedure ImplSign(const AD: IXof; AH, &AS, APk: TCryptoLibByteArray; APkOff: Int32;
    const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
    ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
  procedure ImplSign(const ASk: TCryptoLibByteArray; ASkOff: Int32; const ACtx: TCryptoLibByteArray;
    APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
    ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
  procedure ImplSign(const ASk: TCryptoLibByteArray; ASkOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
    const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
    ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
  function ImplVerify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray;
    APkOff: Int32; const ACtx: TCryptoLibByteArray; APhflag: Byte;
    const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload;
  function ImplVerify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
    const ACtx: TCryptoLibByteArray; APhflag: Byte;
    const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload;
  class procedure InitPointAffine(var AR: TPointAffine); static;
  class procedure InitPointProjective(var AR: TPointProjective); static;
  class procedure InitPointTemp(var AR: TPointTemp); static;
  class procedure InvertZs(APoints: TCryptoLibGenericArray<TPointProjective>); static;
  class function NormalizeToNeutralElementVar(var AP: TPointProjective): Boolean; static;
  class procedure NormalizeToAffine(var AP: TPointProjective; var AR: TPointAffine); static;
  class procedure PointAdd(var AP: TPointAffine; var AR: TPointProjective; var AT: TPointTemp); overload; static;
  class procedure PointAdd(var AP: TPointProjective; var AR: TPointProjective; var AT: TPointTemp); overload; static;
  class procedure PointAddVar(ANegate: Boolean; var AP: TPointAffine; var AR: TPointProjective; var AT: TPointTemp); overload; static;
  class procedure PointAddVar(ANegate: Boolean; var AP: TPointProjective; var AR: TPointProjective; var AT: TPointTemp); overload; static;
  class procedure PointCopy(var AP: TPointAffine; var AR: TPointProjective); overload; static;
  class procedure PointCopy(var AP: TPointProjective; var AR: TPointProjective); overload; static;
  class procedure PointDouble(var AR: TPointProjective; var AT: TPointTemp); static;
  class procedure PointLookup(ABlock, AIndex: Int32; var AP: TPointAffine); overload; static;
  class procedure PointLookup(const AX: TCryptoLibUInt32Array; AN: Int32; const ATable: TCryptoLibUInt32Array; var AR: TPointProjective); overload; static;
  class procedure PointLookup15(const ATable: TCryptoLibUInt32Array; var AR: TPointProjective); static;
  class function PointPrecompute(var AP: TPointProjective; ACount: Int32; var AT: TPointTemp): TCryptoLibUInt32Array; overload; static;
  class procedure PointPrecompute(var AP: TPointAffine; APoints: TCryptoLibGenericArray<TPointProjective>;
    APointsOff, APointsLen: Int32; var AT: TPointTemp); overload; static;
  class procedure PointSetNeutral(var AP: TPointProjective); static;
  class procedure PruneScalar(const AN: TCryptoLibByteArray; ANOff: Int32; const AR: TCryptoLibByteArray); static;
  class procedure ScalarMult(const AK: TCryptoLibByteArray; var AP: TPointProjective; var AR: TPointProjective); static;
  class procedure ScalarMultBase(const AK: TCryptoLibByteArray; var AR: TPointProjective); static;
  class procedure ScalarMultBaseEncoded(const AK, AR: TCryptoLibByteArray; AROff: Int32); static;
  class procedure ScalarMultOrderVar(var AP: TPointAffine; var AR: TPointProjective); static;
  class procedure ScalarMultStraus225Var(const ANb: TCryptoLibUInt32Array; const ANp: TCryptoLibUInt32Array;
    var AP: TPointAffine; const ANq: TCryptoLibUInt32Array; var AQ: TPointAffine; var AR: TPointProjective); static;
  strict protected
    function CreateXof(): IXof; virtual;
  public
  class var
    PrehashSize: Int32;
    PublicKeySize: Int32;
    SecretKeySize: Int32;
    SignatureSize: Int32;

    class procedure EncodePublicPoint(const APublicPoint: IPublicPoint; const APk: TCryptoLibByteArray; APkOff: Int32); static;

    function CreatePrehash(): IXof;

    procedure GeneratePrivateKey(const ARandom: ISecureRandom; const AK: TCryptoLibByteArray);

    procedure GeneratePublicKey(const ASk: TCryptoLibByteArray; ASkOff: Int32;
      APk: TCryptoLibByteArray; APkOff: Int32); overload;

    function GeneratePublicKey(const ASk: TCryptoLibByteArray; ASkOff: Int32): IPublicPoint; overload;

    class procedure Precompute; static;

    class procedure ScalarMultBaseXY(const AK: TCryptoLibByteArray; AKOff: Int32;
      const AX, AY: TCryptoLibUInt32Array); static;

    procedure Sign(const ASk: TCryptoLibByteArray; ASkOff: Int32; const ACtx: TCryptoLibByteArray;
      const AM: TCryptoLibByteArray; AMOff, AMLen: Int32; ASig: TCryptoLibByteArray; ASigOff: Int32); overload;

    procedure Sign(const ASk: TCryptoLibByteArray; ASkOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
      const ACtx: TCryptoLibByteArray; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
      ASig: TCryptoLibByteArray; ASigOff: Int32); overload;

    procedure SignPrehash(const ASk: TCryptoLibByteArray; ASkOff: Int32; const ACtx: TCryptoLibByteArray;
      const APh: TCryptoLibByteArray; APhOff: Int32; ASig: TCryptoLibByteArray; ASigOff: Int32); overload;

    procedure SignPrehash(const ASk: TCryptoLibByteArray; ASkOff: Int32; const APk: TCryptoLibByteArray;
      APkOff: Int32; const ACtx: TCryptoLibByteArray; const APh: TCryptoLibByteArray; APhOff: Int32;
      ASig: TCryptoLibByteArray; ASigOff: Int32); overload;

    procedure SignPrehash(const ASk: TCryptoLibByteArray; ASkOff: Int32; const ACtx: TCryptoLibByteArray;
      const APh: IXof; ASig: TCryptoLibByteArray; ASigOff: Int32); overload;

    procedure SignPrehash(const ASk: TCryptoLibByteArray; ASkOff: Int32; const APk: TCryptoLibByteArray;
      APkOff: Int32; const ACtx: TCryptoLibByteArray; const APh: IXof;
      ASig: TCryptoLibByteArray; ASigOff: Int32); overload;

    class function ValidatePublicKeyFull(const APk: TCryptoLibByteArray; APkOff: Int32): Boolean; static;

    class function ValidatePublicKeyFullExport(const APk: TCryptoLibByteArray; APkOff: Int32): IPublicPoint; static;

    class function ValidatePublicKeyPartial(const APk: TCryptoLibByteArray; APkOff: Int32): Boolean; static;

    class function ValidatePublicKeyPartialExport(const APk: TCryptoLibByteArray; APkOff: Int32): IPublicPoint; static;

    function Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray;
      APkOff: Int32; const ACtx: TCryptoLibByteArray; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload;

    function Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
      const ACtx: TCryptoLibByteArray; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload;

    function VerifyPrehash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray;
      APkOff: Int32; const ACtx: TCryptoLibByteArray; const APh: TCryptoLibByteArray; APhOff: Int32): Boolean; overload;

    function VerifyPrehash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
      const ACtx: TCryptoLibByteArray; const APh: TCryptoLibByteArray; APhOff: Int32): Boolean; overload;

    function VerifyPrehash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray;
      APkOff: Int32; const ACtx: TCryptoLibByteArray; const APh: IXof): Boolean; overload;

    function VerifyPrehash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
      const ACtx: TCryptoLibByteArray; const APh: IXof): Boolean; overload;
  end;

implementation

{ TEd448.TPublicPoint }

constructor TEd448.TPublicPoint.Create(const AData: TCryptoLibUInt32Array);
begin
  inherited Create();
  FData := AData;
end;

function TEd448.TPublicPoint.GetData: TCryptoLibUInt32Array;
begin
  Result := FData;
end;

{ TEd448 }

class constructor TEd448.Create;
begin
  FPrecompLock := TCriticalSection.Create;
  Boot;
end;

class destructor TEd448.Destroy;
begin
  FPrecompLock.Free;
end;

class procedure TEd448.Boot;
begin
  PrehashSize := 64;
  PublicKeySize := PointBytes;
  SecretKeySize := 57;
  SignatureSize := PointBytes + ScalarBytes;

  FDom4Prefix := TCryptoLibByteArray.Create($53, $69, $67, $45, $64, $34, $34, $38);

  FP := TCryptoLibUInt32Array.Create($FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFE, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF);

  FB_x := TCryptoLibUInt32Array.Create($070CC05E, $026A82BC, $00938E26, $080E18B0,
    $0511433B, $0F72AB66, $0412AE1A, $0A3D3A46, $0A6DE324, $00F1767E, $04657047,
    $036DA9E1, $05A622BF, $0ED221D1, $066BED0D, $04F1970C);
  FB_y := TCryptoLibUInt32Array.Create($0230FA14, $008795BF, $07C8AD98, $0132C4ED,
    $09C4FDBD, $01CE67C3, $073AD3FF, $005A0C2D, $07789C1E, $0A398408, $0A73736C,
    $0C7624BE, $003756C9, $02488762, $016EB6BC, $0693F467);

  FB225_x := TCryptoLibUInt32Array.Create($06909EE2, $01D7605C, $0995EC8A, $0FC4D970,
    $0CF2B361, $02D82E9D, $01225F55, $007F0EF6, $0AEE9C55, $0A240C13, $05627B54,
    $0D449D1E, $03A44575, $007164A7, $0BD4BD71, $061A15FD);
  FB225_y := TCryptoLibUInt32Array.Create($0D3A9FE4, $030696B9, $07E7E326, $068308C7,
    $0CE0B8C8, $03AC222B, $0304DB8E, $083EE319, $05E5DB0B, $0ECA503B, $0B1C6539,
    $078A8DCE, $02D256BC, $04A8B05E, $0BD9FD57, $0A1C3CB8);
end;

class function TEd448.CalculateS(const AR, AK, &AS: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LT: TCryptoLibUInt32Array;
  LU, LV: TCryptoLibUInt32Array;
  LResult: TCryptoLibByteArray;
begin
  System.SetLength(LT, ScalarUints * 2);
  TScalar448.Decode(AR, LT);
  System.SetLength(LU, ScalarUints);
  TScalar448.Decode(AK, LU);
  System.SetLength(LV, ScalarUints);
  TScalar448.Decode(&AS, LV);

  TNat.MulAddTo(ScalarUints, LU, LV, LT);

  System.SetLength(LResult, ScalarBytes * 2);
  TCodec.Encode32(LT, 0, System.Length(LT), LResult, 0);
  Result := TScalar448.Reduce912(LResult);
end;

class function TEd448.CheckContextVar(const ACtx: TCryptoLibByteArray): Boolean;
begin
  Result := System.Length(ACtx) < 256;
end;

class function TEd448.CheckPoint(var AP: TPointAffine): Int32;
var
  LT, LU, LV: TCryptoLibUInt32Array;
begin
  LT := TX448Field.Create;
  LU := TX448Field.Create;
  LV := TX448Field.Create;

  TX448Field.Sqr(AP.X, LU);
  TX448Field.Sqr(AP.Y, LV);
  TX448Field.Mul(LU, LV, LT);
  TX448Field.Add(LU, LV, LU);
  TX448Field.Mul(LT, C_d, LT);
  TX448Field.SubOne(LT);
  TX448Field.Add(LT, LU, LT);
  TX448Field.Normalize(LT);
  TX448Field.Normalize(LV);

  Result := TX448Field.IsZero(LT) and (not TX448Field.IsZero(LV));
end;

class function TEd448.CheckPoint(const AP: TPointProjective): Int32;
var
  LT, LU, LV, LW: TCryptoLibUInt32Array;
begin
  LT := TX448Field.Create;
  LU := TX448Field.Create;
  LV := TX448Field.Create;
  LW := TX448Field.Create;

  TX448Field.Sqr(AP.X, LU);
  TX448Field.Sqr(AP.Y, LV);
  TX448Field.Sqr(AP.Z, LW);
  TX448Field.Mul(LU, LV, LT);
  TX448Field.Add(LU, LV, LU);
  TX448Field.Mul(LU, LW, LU);
  TX448Field.Sqr(LW, LW);
  TX448Field.Mul(LT, C_d, LT);
  TX448Field.Sub(LT, LW, LT);
  TX448Field.Add(LT, LU, LT);
  TX448Field.Normalize(LT);
  TX448Field.Normalize(LV);
  TX448Field.Normalize(LW);

  Result := TX448Field.IsZero(LT) and (not TX448Field.IsZero(LV)) and (not TX448Field.IsZero(LW));
end;

class function TEd448.CheckPointOrderVar(var AP: TPointAffine): Boolean;
var
  LR: TPointProjective;
begin
  InitPointProjective(LR);
  ScalarMultOrderVar(AP, LR);
  Result := NormalizeToNeutralElementVar(LR);
end;

class function TEd448.CheckPointFullVar(const AP: TCryptoLibByteArray): Boolean;
var
  LY13, LT0, LT1, LYi, LY0: UInt32;
  LI: Int32;
begin
  if (AP[PointBytes - 1] and $7F) <> $00 then
  begin
    Result := False;
    Exit;
  end;

  LY13 := TCodec.Decode32(AP, 52);
  LT0 := LY13;
  LT1 := LY13 xor FP[13];

  for LI := CoordUints - 2 downto 1 do
  begin
    LYi := TCodec.Decode32(AP, LI * 4);
    if (LT1 = 0) and (LYi > FP[LI]) then
    begin
      Result := False;
      Exit;
    end;
    LT0 := LT0 or LYi;
    LT1 := LT1 or (LYi xor FP[LI]);
  end;

  LY0 := TCodec.Decode32(AP, 0);
  if (LT0 = 0) and (LY0 <= 1) then
  begin
    Result := False;
    Exit;
  end;
  if (LT1 = 0) and (LY0 >= (FP[0] - 1)) then
  begin
    Result := False;
    Exit;
  end;

  Result := True;
end;

class function TEd448.CheckPointVar(const AP: TCryptoLibByteArray): Boolean;
var
  LLast, LI: Int32;
begin
  if (AP[PointBytes - 1] and $7F) <> $00 then
  begin
    Result := False;
    Exit;
  end;
  if TCodec.Decode32(AP, 52) < FP[13] then
  begin
    Result := True;
    Exit;
  end;

  if AP[28] = $FF then
    LLast := 7
  else
    LLast := 0;

  for LI := CoordUints - 2 downto LLast do
  begin
    if TCodec.Decode32(AP, LI * 4) < FP[LI] then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TEd448.CopyBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): TCryptoLibByteArray;
begin
  System.SetLength(Result, ALen);
  System.Move(ABuf[AOff], Result[0], ALen);
end;

function TEd448.CreateAndValidateXof(): IXof;
begin
  Result := CreateXof();
end;

function TEd448.CreatePrehash(): IXof;
begin
  Result := CreateAndValidateXof();
end;

function TEd448.CreateXof(): IXof;
begin
  Result := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
end;

class function TEd448.DecodePointVar(const AP: TCryptoLibByteArray; ANegate: Boolean; var AR: TPointAffine): Boolean;
var
  LX0: Int32;
  LU, LV: TCryptoLibUInt32Array;
begin
  LX0 := (AP[PointBytes - 1] and $80) shr 7;

  TX448Field.Decode448(AP, AR.Y);

  LU := TX448Field.Create;
  LV := TX448Field.Create;

  TX448Field.Sqr(AR.Y, LU);
  TX448Field.Mul(LU, C_d, LV);
  TX448Field.Negate(LU, LU);
  TX448Field.AddOne(LU);
  TX448Field.AddOne(LV);

  if not TX448Field.SqrtRatioVar(LU, LV, AR.X) then
  begin
    Result := False;
    Exit;
  end;

  TX448Field.Normalize(AR.X);
  if (LX0 = 1) and TX448Field.IsZeroVar(AR.X) then
  begin
    Result := False;
    Exit;
  end;

  if ANegate xor (LX0 <> Int32(AR.X[0] and 1)) then
  begin
    TX448Field.Negate(AR.X, AR.X);
    TX448Field.Normalize(AR.X);
  end;

  Result := True;
end;

class procedure TEd448.Dom4(const AD: IXof; APhflag: Byte; const ACtx: TCryptoLibByteArray);
var
  LN: Int32;
  LT: TCryptoLibByteArray;
begin
  LN := System.Length(FDom4Prefix);
  System.SetLength(LT, LN + 2 + System.Length(ACtx));
  System.Move(FDom4Prefix[0], LT[0], LN);
  LT[LN] := APhflag;
  LT[LN + 1] := Byte(System.Length(ACtx));
  if System.Length(ACtx) > 0 then
    System.Move(ACtx[0], LT[LN + 2], System.Length(ACtx));
  AD.BlockUpdate(LT, 0, System.Length(LT));
end;

class procedure TEd448.EncodePoint(var AP: TPointAffine; const AR: TCryptoLibByteArray; AROff: Int32);
begin
  TX448Field.Encode(AP.Y, AR, AROff);
  AR[AROff + PointBytes - 1] := Byte((AP.X[0] and 1) shl 7);
end;

class procedure TEd448.EncodePublicPoint(const APublicPoint: IPublicPoint; const APk: TCryptoLibByteArray; APkOff: Int32);
begin
  TX448Field.Encode(APublicPoint.Data, TX448Field.Size, APk, APkOff);
  APk[APkOff + PointBytes - 1] := Byte((APublicPoint.Data[0] and 1) shl 7);
end;

class function TEd448.EncodeResult(var AP: TPointProjective; const AR: TCryptoLibByteArray; AROff: Int32): Int32;
var
  LQ: TPointAffine;
begin
  InitPointAffine(LQ);
  NormalizeToAffine(AP, LQ);
  Result := CheckPoint(LQ);
  EncodePoint(LQ, AR, AROff);
end;

class function TEd448.ExportPoint(var AP: TPointAffine): IPublicPoint;
var
  LData: TCryptoLibUInt32Array;
begin
  System.SetLength(LData, TX448Field.Size * 2);
  TX448Field.Copy(AP.X, 0, LData, 0);
  TX448Field.Copy(AP.Y, 0, LData, TX448Field.Size);
  Result := TPublicPoint.Create(LData);
end;

class function TEd448.GetWindow4(const AX: TCryptoLibUInt32Array; AN: Int32): UInt32;
var
  LW, LB: Int32;
begin
  LW := Int32(UInt32(AN) shr 3);
  LB := (AN and 7) shl 2;
  Result := (AX[LW] shr LB) and 15;
end;

class procedure TEd448.InitPointAffine(var AR: TPointAffine);
begin
  AR.X := TX448Field.Create;
  AR.Y := TX448Field.Create;
end;

class procedure TEd448.InitPointProjective(var AR: TPointProjective);
begin
  AR.X := TX448Field.Create;
  AR.Y := TX448Field.Create;
  AR.Z := TX448Field.Create;
end;

class procedure TEd448.InitPointTemp(var AR: TPointTemp);
begin
  AR.R0 := TX448Field.Create;
  AR.R1 := TX448Field.Create;
  AR.R2 := TX448Field.Create;
  AR.R3 := TX448Field.Create;
  AR.R4 := TX448Field.Create;
  AR.R5 := TX448Field.Create;
  AR.R6 := TX448Field.Create;
  AR.R7 := TX448Field.Create;
end;

class procedure TEd448.InvertZs(APoints: TCryptoLibGenericArray<TPointProjective>);
var
  LCount, LI, LJ: Int32;
  LCs: TCryptoLibUInt32Array;
  LU, LT: TCryptoLibUInt32Array;
begin
  LCount := System.Length(APoints);
  LCs := TX448Field.CreateTable(LCount);

  LU := TX448Field.Create;
  TX448Field.Copy(APoints[0].Z, 0, LU, 0);
  TX448Field.Copy(LU, 0, LCs, 0);

  LI := 0;
  while LI + 1 < LCount do
  begin
    Inc(LI);
    TX448Field.Mul(LU, APoints[LI].Z, LU);
    TX448Field.Copy(LU, 0, LCs, LI * TX448Field.Size);
  end;

  TX448Field.InvVar(LU, LU);

  LT := TX448Field.Create;

  while LI > 0 do
  begin
    LJ := LI;
    Dec(LI);
    TX448Field.Copy(LCs, LI * TX448Field.Size, LT, 0);
    TX448Field.Mul(LT, LU, LT);
    TX448Field.Mul(LU, APoints[LJ].Z, LU);
    TX448Field.Copy(LT, 0, APoints[LJ].Z, 0);
  end;

  TX448Field.Copy(LU, 0, APoints[0].Z, 0);
end;

class procedure TEd448.NormalizeToAffine(var AP: TPointProjective; var AR: TPointAffine);
begin
  TX448Field.Inv(AP.Z, AR.Y);
  TX448Field.Mul(AR.Y, AP.X, AR.X);
  TX448Field.Mul(AR.Y, AP.Y, AR.Y);
  TX448Field.Normalize(AR.X);
  TX448Field.Normalize(AR.Y);
end;

class function TEd448.NormalizeToNeutralElementVar(var AP: TPointProjective): Boolean;
begin
  TX448Field.Normalize(AP.X);
  TX448Field.Normalize(AP.Y);
  TX448Field.Normalize(AP.Z);
  Result := TX448Field.IsZeroVar(AP.X) and (not TX448Field.IsZeroVar(AP.Y)) and TX448Field.AreEqualVar(AP.Y, AP.Z);
end;

class procedure TEd448.PointAdd(var AP: TPointAffine; var AR: TPointProjective; var AT: TPointTemp);
var
  LB, LC, LD, LE, LF, LG, LH: TCryptoLibUInt32Array;
begin
  LB := AT.R1; LC := AT.R2; LD := AT.R3; LE := AT.R4;
  LF := AT.R5; LG := AT.R6; LH := AT.R7;

  TX448Field.Sqr(AR.Z, LB);
  TX448Field.Mul(AP.X, AR.X, LC);
  TX448Field.Mul(AP.Y, AR.Y, LD);
  TX448Field.Mul(LC, LD, LE);
  TX448Field.Mul(LE, C_d, LE);
  TX448Field.Add(LB, LE, LF);
  TX448Field.Sub(LB, LE, LG);
  TX448Field.Add(AP.Y, AP.X, LH);
  TX448Field.Add(AR.Y, AR.X, LE);
  TX448Field.Mul(LH, LE, LH);
  TX448Field.Add(LD, LC, LB);
  TX448Field.Sub(LD, LC, LE);
  TX448Field.Carry(LB);
  TX448Field.Sub(LH, LB, LH);
  TX448Field.Mul(LH, AR.Z, LH);
  TX448Field.Mul(LE, AR.Z, LE);
  TX448Field.Mul(LF, LH, AR.X);
  TX448Field.Mul(LE, LG, AR.Y);
  TX448Field.Mul(LF, LG, AR.Z);
end;

class procedure TEd448.PointAdd(var AP: TPointProjective; var AR: TPointProjective; var AT: TPointTemp);
var
  LA, LB, LC, LD, LE, LF, LG, LH: TCryptoLibUInt32Array;
begin
  LA := AT.R0; LB := AT.R1; LC := AT.R2; LD := AT.R3;
  LE := AT.R4; LF := AT.R5; LG := AT.R6; LH := AT.R7;

  TX448Field.Mul(AP.Z, AR.Z, LA);
  TX448Field.Sqr(LA, LB);
  TX448Field.Mul(AP.X, AR.X, LC);
  TX448Field.Mul(AP.Y, AR.Y, LD);
  TX448Field.Mul(LC, LD, LE);
  TX448Field.Mul(LE, C_d, LE);
  TX448Field.Add(LB, LE, LF);
  TX448Field.Sub(LB, LE, LG);
  TX448Field.Add(AP.Y, AP.X, LH);
  TX448Field.Add(AR.Y, AR.X, LE);
  TX448Field.Mul(LH, LE, LH);
  TX448Field.Add(LD, LC, LB);
  TX448Field.Sub(LD, LC, LE);
  TX448Field.Carry(LB);
  TX448Field.Sub(LH, LB, LH);
  TX448Field.Mul(LH, LA, LH);
  TX448Field.Mul(LE, LA, LE);
  TX448Field.Mul(LF, LH, AR.X);
  TX448Field.Mul(LE, LG, AR.Y);
  TX448Field.Mul(LF, LG, AR.Z);
end;

class procedure TEd448.PointAddVar(ANegate: Boolean; var AP: TPointAffine; var AR: TPointProjective; var AT: TPointTemp);
var
  LB, LC, LD, LE, LF, LG, LH: TCryptoLibUInt32Array;
  LNb, LNe, LNf, LNg: TCryptoLibUInt32Array;
begin
  LB := AT.R1; LC := AT.R2; LD := AT.R3; LE := AT.R4;
  LF := AT.R5; LG := AT.R6; LH := AT.R7;

  if ANegate then
  begin
    LNb := LE; LNe := LB; LNf := LG; LNg := LF;
    TX448Field.Sub(AP.Y, AP.X, LH);
  end
  else
  begin
    LNb := LB; LNe := LE; LNf := LF; LNg := LG;
    TX448Field.Add(AP.Y, AP.X, LH);
  end;

  TX448Field.Sqr(AR.Z, LB);
  TX448Field.Mul(AP.X, AR.X, LC);
  TX448Field.Mul(AP.Y, AR.Y, LD);
  TX448Field.Mul(LC, LD, LE);
  TX448Field.Mul(LE, C_d, LE);
  TX448Field.Add(LB, LE, LNf);
  TX448Field.Sub(LB, LE, LNg);
  TX448Field.Add(AR.Y, AR.X, LE);
  TX448Field.Mul(LH, LE, LH);
  TX448Field.Add(LD, LC, LNb);
  TX448Field.Sub(LD, LC, LNe);
  TX448Field.Carry(LNb);
  TX448Field.Sub(LH, LB, LH);
  TX448Field.Mul(LH, AR.Z, LH);
  TX448Field.Mul(LE, AR.Z, LE);
  TX448Field.Mul(LF, LH, AR.X);
  TX448Field.Mul(LE, LG, AR.Y);
  TX448Field.Mul(LF, LG, AR.Z);
end;

class procedure TEd448.PointAddVar(ANegate: Boolean; var AP: TPointProjective; var AR: TPointProjective; var AT: TPointTemp);
var
  LA, LB, LC, LD, LE, LF, LG, LH: TCryptoLibUInt32Array;
  LNb, LNe, LNf, LNg: TCryptoLibUInt32Array;
begin
  LA := AT.R0; LB := AT.R1; LC := AT.R2; LD := AT.R3;
  LE := AT.R4; LF := AT.R5; LG := AT.R6; LH := AT.R7;

  if ANegate then
  begin
    LNb := LE; LNe := LB; LNf := LG; LNg := LF;
    TX448Field.Sub(AP.Y, AP.X, LH);
  end
  else
  begin
    LNb := LB; LNe := LE; LNf := LF; LNg := LG;
    TX448Field.Add(AP.Y, AP.X, LH);
  end;

  TX448Field.Mul(AP.Z, AR.Z, LA);
  TX448Field.Sqr(LA, LB);
  TX448Field.Mul(AP.X, AR.X, LC);
  TX448Field.Mul(AP.Y, AR.Y, LD);
  TX448Field.Mul(LC, LD, LE);
  TX448Field.Mul(LE, C_d, LE);
  TX448Field.Add(LB, LE, LNf);
  TX448Field.Sub(LB, LE, LNg);
  TX448Field.Add(AR.Y, AR.X, LE);
  TX448Field.Mul(LH, LE, LH);
  TX448Field.Add(LD, LC, LNb);
  TX448Field.Sub(LD, LC, LNe);
  TX448Field.Carry(LNb);
  TX448Field.Sub(LH, LB, LH);
  TX448Field.Mul(LH, LA, LH);
  TX448Field.Mul(LE, LA, LE);
  TX448Field.Mul(LF, LH, AR.X);
  TX448Field.Mul(LE, LG, AR.Y);
  TX448Field.Mul(LF, LG, AR.Z);
end;

class procedure TEd448.PointCopy(var AP: TPointAffine; var AR: TPointProjective);
begin
  TX448Field.Copy(AP.X, 0, AR.X, 0);
  TX448Field.Copy(AP.Y, 0, AR.Y, 0);
  TX448Field.One(AR.Z);
end;

class procedure TEd448.PointCopy(var AP: TPointProjective; var AR: TPointProjective);
begin
  TX448Field.Copy(AP.X, 0, AR.X, 0);
  TX448Field.Copy(AP.Y, 0, AR.Y, 0);
  TX448Field.Copy(AP.Z, 0, AR.Z, 0);
end;

class procedure TEd448.PointDouble(var AR: TPointProjective; var AT: TPointTemp);
var
  LB, LC, LD, LE, LH, LJ: TCryptoLibUInt32Array;
begin
  LB := AT.R1; LC := AT.R2; LD := AT.R3; LE := AT.R4;
  LH := AT.R7; LJ := AT.R0;

  TX448Field.Add(AR.X, AR.Y, LB);
  TX448Field.Sqr(LB, LB);
  TX448Field.Sqr(AR.X, LC);
  TX448Field.Sqr(AR.Y, LD);
  TX448Field.Add(LC, LD, LE);
  TX448Field.Carry(LE);
  TX448Field.Sqr(AR.Z, LH);
  TX448Field.Add(LH, LH, LH);
  TX448Field.Carry(LH);
  TX448Field.Sub(LE, LH, LJ);
  TX448Field.Sub(LB, LE, LB);
  TX448Field.Sub(LC, LD, LC);
  TX448Field.Mul(LB, LJ, AR.X);
  TX448Field.Mul(LE, LC, AR.Y);
  TX448Field.Mul(LE, LJ, AR.Z);
end;

class procedure TEd448.PointLookup(ABlock, AIndex: Int32; var AP: TPointAffine);
var
  LOff, LI, LCond: Int32;
begin
  LOff := ABlock * PrecompPoints * 2 * TX448Field.Size;
  for LI := 0 to PrecompPoints - 1 do
  begin
    LCond := TBitOperations.Asr32((LI xor AIndex) - 1, 31);
    TX448Field.CMov(LCond, FPrecompBaseComb, LOff, AP.X, 0); Inc(LOff, TX448Field.Size);
    TX448Field.CMov(LCond, FPrecompBaseComb, LOff, AP.Y, 0); Inc(LOff, TX448Field.Size);
  end;
end;

class procedure TEd448.PointLookup(const AX: TCryptoLibUInt32Array; AN: Int32;
  const ATable: TCryptoLibUInt32Array; var AR: TPointProjective);
var
  LW: UInt32;
  LSign, LAbs, LI, LCond, LOff: Int32;
begin
  LW := GetWindow4(AX, AN);
  LSign := Int32(LW shr (4 - 1)) xor 1;
  LAbs := (Int32(LW) xor (-LSign)) and 7;

  LOff := 0;
  for LI := 0 to 7 do
  begin
    LCond := TBitOperations.Asr32((LI xor LAbs) - 1, 31);
    TX448Field.CMov(LCond, ATable, LOff, AR.X, 0); Inc(LOff, TX448Field.Size);
    TX448Field.CMov(LCond, ATable, LOff, AR.Y, 0); Inc(LOff, TX448Field.Size);
    TX448Field.CMov(LCond, ATable, LOff, AR.Z, 0); Inc(LOff, TX448Field.Size);
  end;

  TX448Field.CNegate(LSign, AR.X);
end;

class procedure TEd448.PointLookup15(const ATable: TCryptoLibUInt32Array; var AR: TPointProjective);
var
  LOff: Int32;
begin
  LOff := TX448Field.Size * 3 * 7;
  TX448Field.Copy(ATable, LOff, AR.X, 0); Inc(LOff, TX448Field.Size);
  TX448Field.Copy(ATable, LOff, AR.Y, 0); Inc(LOff, TX448Field.Size);
  TX448Field.Copy(ATable, LOff, AR.Z, 0);
end;

class function TEd448.PointPrecompute(var AP: TPointProjective; ACount: Int32; var AT: TPointTemp): TCryptoLibUInt32Array;
var
  LQ, LD: TPointProjective;
  LTable: TCryptoLibUInt32Array;
  LOff, LI: Int32;
begin
  InitPointProjective(LQ);
  PointCopy(AP, LQ);

  InitPointProjective(LD);
  PointCopy(AP, LD);
  PointDouble(LD, AT);

  LTable := TX448Field.CreateTable(ACount * 3);
  LOff := 0;

  LI := 0;
  while True do
  begin
    TX448Field.Copy(LQ.X, 0, LTable, LOff); Inc(LOff, TX448Field.Size);
    TX448Field.Copy(LQ.Y, 0, LTable, LOff); Inc(LOff, TX448Field.Size);
    TX448Field.Copy(LQ.Z, 0, LTable, LOff); Inc(LOff, TX448Field.Size);

    Inc(LI);
    if LI = ACount then
      Break;

    PointAdd(LD, LQ, AT);
  end;

  Result := LTable;
end;

class procedure TEd448.PointPrecompute(var AP: TPointAffine; APoints: TCryptoLibGenericArray<TPointProjective>;
  APointsOff, APointsLen: Int32; var AT: TPointTemp);
var
  LD: TPointProjective;
  LI: Int32;
begin
  InitPointProjective(LD);
  PointCopy(AP, LD);
  PointDouble(LD, AT);

  InitPointProjective(APoints[APointsOff]);
  PointCopy(AP, APoints[APointsOff]);

  for LI := 1 to APointsLen - 1 do
  begin
    InitPointProjective(APoints[APointsOff + LI]);
    PointCopy(APoints[APointsOff + LI - 1], APoints[APointsOff + LI]);
    PointAdd(LD, APoints[APointsOff + LI], AT);
  end;
end;

class procedure TEd448.PointSetNeutral(var AP: TPointProjective);
begin
  TX448Field.Zero(AP.X);
  TX448Field.One(AP.Y);
  TX448Field.One(AP.Z);
end;

class procedure TEd448.Precompute;
var
  LWnafPoints, LCombPoints, LTotalPoints, LPointsIndex: Int32;
  LPoints: TCryptoLibGenericArray<TPointProjective>;
  LT: TPointTemp;
  LB, LB225: TPointAffine;
  LP: TPointProjective;
  LToothPowers: TCryptoLibGenericArray<TPointProjective>;
  LBlock, LTooth, LSpacing, LSize, LJ, LI, LOff: Int32;
begin
  FPrecompLock.Acquire;
  try
    if FPrecompBaseComb <> nil then
      Exit;

    LWnafPoints := 1 shl (WnafWidthBase - 2);
    LCombPoints := PrecompBlocks * PrecompPoints;
    LTotalPoints := LWnafPoints * 2 + LCombPoints;

    System.SetLength(LPoints, LTotalPoints);
    InitPointTemp(LT);

    InitPointAffine(LB);
    TX448Field.Copy(FB_x, 0, LB.X, 0);
    TX448Field.Copy(FB_y, 0, LB.Y, 0);

    PointPrecompute(LB, LPoints, 0, LWnafPoints, LT);

    InitPointAffine(LB225);
    TX448Field.Copy(FB225_x, 0, LB225.X, 0);
    TX448Field.Copy(FB225_y, 0, LB225.Y, 0);

    PointPrecompute(LB225, LPoints, LWnafPoints, LWnafPoints, LT);

    InitPointProjective(LP);
    PointCopy(LB, LP);

    LPointsIndex := LWnafPoints * 2;
    System.SetLength(LToothPowers, PrecompTeeth);
    for LTooth := 0 to PrecompTeeth - 1 do
    begin
      InitPointProjective(LToothPowers[LTooth]);
    end;

    for LBlock := 0 to PrecompBlocks - 1 do
    begin
      InitPointProjective(LPoints[LPointsIndex]);

      for LTooth := 0 to PrecompTeeth - 1 do
      begin
        if LTooth = 0 then
          PointCopy(LP, LPoints[LPointsIndex])
        else
          PointAdd(LP, LPoints[LPointsIndex], LT);

        PointDouble(LP, LT);
        PointCopy(LP, LToothPowers[LTooth]);

        if LBlock + LTooth <> PrecompBlocks + PrecompTeeth - 2 then
        begin
          for LSpacing := 1 to PrecompSpacing - 1 do
          begin
            PointDouble(LP, LT);
          end;
        end;
      end;

      Inc(LPointsIndex);

      TX448Field.Negate(LPoints[LPointsIndex - 1].X, LPoints[LPointsIndex - 1].X);

      for LTooth := 0 to PrecompTeeth - 2 do
      begin
        LSize := 1 shl LTooth;
        for LJ := 0 to LSize - 1 do
        begin
          InitPointProjective(LPoints[LPointsIndex]);
          PointCopy(LPoints[LPointsIndex - LSize], LPoints[LPointsIndex]);
          PointAdd(LToothPowers[LTooth], LPoints[LPointsIndex], LT);
          Inc(LPointsIndex);
        end;
      end;
    end;

    InvertZs(LPoints);

    System.SetLength(FPrecompBaseWnaf, LWnafPoints);
    for LI := 0 to LWnafPoints - 1 do
    begin
      InitPointAffine(FPrecompBaseWnaf[LI]);
      TX448Field.Mul(LPoints[LI].X, LPoints[LI].Z, FPrecompBaseWnaf[LI].X);
      TX448Field.Normalize(FPrecompBaseWnaf[LI].X);
      TX448Field.Mul(LPoints[LI].Y, LPoints[LI].Z, FPrecompBaseWnaf[LI].Y);
      TX448Field.Normalize(FPrecompBaseWnaf[LI].Y);
    end;

    System.SetLength(FPrecompBase225Wnaf, LWnafPoints);
    for LI := 0 to LWnafPoints - 1 do
    begin
      InitPointAffine(FPrecompBase225Wnaf[LI]);
      TX448Field.Mul(LPoints[LWnafPoints + LI].X, LPoints[LWnafPoints + LI].Z, FPrecompBase225Wnaf[LI].X);
      TX448Field.Normalize(FPrecompBase225Wnaf[LI].X);
      TX448Field.Mul(LPoints[LWnafPoints + LI].Y, LPoints[LWnafPoints + LI].Z, FPrecompBase225Wnaf[LI].Y);
      TX448Field.Normalize(FPrecompBase225Wnaf[LI].Y);
    end;

    FPrecompBaseComb := TX448Field.CreateTable(LCombPoints * 2);
    LOff := 0;
    for LI := LWnafPoints * 2 to LTotalPoints - 1 do
    begin
      TX448Field.Mul(LPoints[LI].X, LPoints[LI].Z, LPoints[LI].X);
      TX448Field.Normalize(LPoints[LI].X);
      TX448Field.Mul(LPoints[LI].Y, LPoints[LI].Z, LPoints[LI].Y);
      TX448Field.Normalize(LPoints[LI].Y);

      TX448Field.Copy(LPoints[LI].X, 0, FPrecompBaseComb, LOff); Inc(LOff, TX448Field.Size);
      TX448Field.Copy(LPoints[LI].Y, 0, FPrecompBaseComb, LOff); Inc(LOff, TX448Field.Size);
    end;
  finally
    FPrecompLock.Release;
  end;
end;

class procedure TEd448.PruneScalar(const AN: TCryptoLibByteArray; ANOff: Int32; const AR: TCryptoLibByteArray);
begin
  System.Move(AN[ANOff], AR[0], ScalarBytes - 1);
  AR[0] := AR[0] and $FC;
  AR[ScalarBytes - 2] := AR[ScalarBytes - 2] or $80;
  AR[ScalarBytes - 1] := $00;
end;

class procedure TEd448.ScalarMult(const AK: TCryptoLibByteArray; var AP: TPointProjective; var AR: TPointProjective);
var
  LN: TCryptoLibUInt32Array;
  LQ: TPointProjective;
  LT: TPointTemp;
  LTable: TCryptoLibUInt32Array;
  LW, LI: Int32;
begin
  System.SetLength(LN, ScalarUints + 1);
  TScalar448.Decode(AK, LN);
  TScalar448.ToSignedDigits(449, LN, LN);

  InitPointProjective(LQ);
  InitPointTemp(LT);
  LTable := PointPrecompute(AP, 8, LT);

  PointLookup15(LTable, AR);
  PointAdd(AP, AR, LT);

  LW := 111;
  while True do
  begin
    PointLookup(LN, LW, LTable, LQ);
    PointAdd(LQ, AR, LT);

    Dec(LW);
    if LW < 0 then
      Break;

    for LI := 0 to 3 do
    begin
      PointDouble(AR, LT);
    end;
  end;
end;

class procedure TEd448.ScalarMultBase(const AK: TCryptoLibByteArray; var AR: TPointProjective);
var
  LN: TCryptoLibUInt32Array;
  LP: TPointAffine;
  LT: TPointTemp;
  LCOff, LTPos, LBlock, LTooth: Int32;
  LW, LTBit: UInt32;
  LSign, LAbs: Int32;
begin
  Precompute;

  System.SetLength(LN, ScalarUints + 1);
  TScalar448.Decode(AK, LN);
  TScalar448.ToSignedDigits(PrecompRange, LN, LN);

  InitPointAffine(LP);
  InitPointTemp(LT);

  PointSetNeutral(AR);

  LCOff := PrecompSpacing - 1;
  while True do
  begin
    LTPos := LCOff;

    for LBlock := 0 to PrecompBlocks - 1 do
    begin
      LW := 0;
      for LTooth := 0 to PrecompTeeth - 1 do
      begin
        LTBit := LN[TBitOperations.Asr32(LTPos, 5)] shr (LTPos and $1F);
        LW := LW and (not (UInt32(1) shl LTooth));
        LW := LW xor (LTBit shl LTooth);
        Inc(LTPos, PrecompSpacing);
      end;

      LSign := Int32(LW shr (PrecompTeeth - 1)) and 1;
      LAbs := (Int32(LW) xor (-LSign)) and PrecompMask;

      PointLookup(LBlock, LAbs, LP);
      TX448Field.CNegate(LSign, LP.X);
      PointAdd(LP, AR, LT);
    end;

    Dec(LCOff);
    if LCOff < 0 then
      Break;

    PointDouble(AR, LT);
  end;
end;

class procedure TEd448.ScalarMultBaseEncoded(const AK, AR: TCryptoLibByteArray; AROff: Int32);
var
  LP: TPointProjective;
begin
  InitPointProjective(LP);
  ScalarMultBase(AK, LP);
  if 0 = EncodeResult(LP, AR, AROff) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);
end;

class procedure TEd448.ScalarMultBaseXY(const AK: TCryptoLibByteArray; AKOff: Int32;
  const AX, AY: TCryptoLibUInt32Array);
var
  LN: TCryptoLibByteArray;
  LP: TPointProjective;
begin
  System.SetLength(LN, ScalarBytes);
  PruneScalar(AK, AKOff, LN);

  InitPointProjective(LP);
  ScalarMultBase(LN, LP);

  if 0 = CheckPoint(LP) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);

  TX448Field.Copy(LP.X, 0, AX, 0);
  TX448Field.Copy(LP.Y, 0, AY, 0);
end;

class procedure TEd448.ScalarMultOrderVar(var AP: TPointAffine; var AR: TPointProjective);
var
  LWs_p: TCryptoLibShortIntArray;
  LCount, LBit, LWp, LIndex: Int32;
  LTp: TCryptoLibGenericArray<TPointProjective>;
  LT: TPointTemp;
begin
  System.SetLength(LWs_p, 447);
  TScalar448.GetOrderWnafVar(WnafWidth225, LWs_p);

  LCount := 1 shl (WnafWidth225 - 2);
  System.SetLength(LTp, LCount);
  InitPointTemp(LT);
  PointPrecompute(AP, LTp, 0, LCount, LT);

  PointSetNeutral(AR);

  LBit := 446;
  while True do
  begin
    LWp := LWs_p[LBit];
    if LWp <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWp, 1) xor TBitOperations.Asr32(LWp, 31);
      PointAddVar(LWp < 0, LTp[LIndex], AR, LT);
    end;

    Dec(LBit);
    if LBit < 0 then
      Break;

    PointDouble(AR, LT);
  end;
end;

class procedure TEd448.ScalarMultStraus225Var(const ANb: TCryptoLibUInt32Array;
  const ANp: TCryptoLibUInt32Array; var AP: TPointAffine;
  const ANq: TCryptoLibUInt32Array; var AQ: TPointAffine;
  var AR: TPointProjective);
var
  LWs_b: TCryptoLibShortIntArray;
  LWs_p, LWs_q: TCryptoLibShortIntArray;
  LCount, LBit, LWb, LWb225, LWp, LWq, LIndex: Int32;
  LTp, LTq: TCryptoLibGenericArray<TPointProjective>;
  LT: TPointTemp;
begin
  Precompute;

  System.SetLength(LWs_b, 450);
  System.SetLength(LWs_p, 225);
  System.SetLength(LWs_q, 225);

  TWnaf.GetSignedVar(ANb, WnafWidthBase, LWs_b);
  TWnaf.GetSignedVar(ANp, WnafWidth225, LWs_p);
  TWnaf.GetSignedVar(ANq, WnafWidth225, LWs_q);

  LCount := 1 shl (WnafWidth225 - 2);
  System.SetLength(LTp, LCount);
  System.SetLength(LTq, LCount);
  InitPointTemp(LT);
  PointPrecompute(AP, LTp, 0, LCount, LT);
  PointPrecompute(AQ, LTq, 0, LCount, LT);

  PointSetNeutral(AR);

  LBit := 225;
  while LBit > 0 do
  begin
    Dec(LBit);
    if (Int32(LWs_b[LBit]) or Int32(LWs_b[225 + LBit]) or Int32(LWs_p[LBit]) or Int32(LWs_q[LBit])) <> 0 then
      Break;
  end;

  while LBit >= 0 do
  begin
    LWb := LWs_b[LBit];
    if LWb <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWb, 1) xor TBitOperations.Asr32(LWb, 31);
      PointAddVar(LWb < 0, FPrecompBaseWnaf[LIndex], AR, LT);
    end;

    LWb225 := LWs_b[225 + LBit];
    if LWb225 <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWb225, 1) xor TBitOperations.Asr32(LWb225, 31);
      PointAddVar(LWb225 < 0, FPrecompBase225Wnaf[LIndex], AR, LT);
    end;

    LWp := LWs_p[LBit];
    if LWp <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWp, 1) xor TBitOperations.Asr32(LWp, 31);
      PointAddVar(LWp < 0, LTp[LIndex], AR, LT);
    end;

    LWq := LWs_q[LBit];
    if LWq <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWq, 1) xor TBitOperations.Asr32(LWq, 31);
      PointAddVar(LWq < 0, LTq[LIndex], AR, LT);
    end;

    PointDouble(AR, LT);
    Dec(LBit);
  end;

  PointDouble(AR, LT);
end;

procedure TEd448.ImplSign(const AD: IXof; AH, &AS, APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
  ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LR, LRR, LK, LSS: TCryptoLibByteArray;
begin
  Dom4(AD, APhflag, ACtx);
  AD.BlockUpdate(AH, ScalarBytes, ScalarBytes);
  AD.BlockUpdate(AM, AMOff, AMLen);
  AD.OutputFinal(AH, 0, System.Length(AH));

  LR := TScalar448.Reduce912(AH);
  System.SetLength(LRR, PointBytes);
  ScalarMultBaseEncoded(LR, LRR, 0);

  Dom4(AD, APhflag, ACtx);
  AD.BlockUpdate(LRR, 0, PointBytes);
  AD.BlockUpdate(APk, APkOff, PointBytes);
  AD.BlockUpdate(AM, AMOff, AMLen);
  AD.OutputFinal(AH, 0, System.Length(AH));

  LK := TScalar448.Reduce912(AH);
  LSS := CalculateS(LR, LK, &AS);

  System.Move(LRR[0], ASig[ASigOff], PointBytes);
  System.Move(LSS[0], ASig[ASigOff + PointBytes], ScalarBytes);
end;

procedure TEd448.ImplSign(const ASk: TCryptoLibByteArray; ASkOff: Int32; const ACtx: TCryptoLibByteArray;
  APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
  ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LD: IXof;
  LH, LS, LPk: TCryptoLibByteArray;
begin
  if not CheckContextVar(ACtx) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);

  LD := CreateAndValidateXof();
  System.SetLength(LH, ScalarBytes * 2);
  LD.BlockUpdate(ASk, ASkOff, SecretKeySize);
  LD.OutputFinal(LH, 0, System.Length(LH));

  System.SetLength(LS, ScalarBytes);
  PruneScalar(LH, 0, LS);

  System.SetLength(LPk, PointBytes);
  ScalarMultBaseEncoded(LS, LPk, 0);

  ImplSign(LD, LH, LS, LPk, 0, ACtx, APhflag, AM, AMOff, AMLen, ASig, ASigOff);
end;

procedure TEd448.ImplSign(const ASk: TCryptoLibByteArray; ASkOff: Int32; const APk: TCryptoLibByteArray;
  APkOff: Int32; const ACtx: TCryptoLibByteArray; APhflag: Byte;
  const AM: TCryptoLibByteArray; AMOff, AMLen: Int32; ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LD: IXof;
  LH, LS: TCryptoLibByteArray;
begin
  if not CheckContextVar(ACtx) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);

  LD := CreateAndValidateXof();
  System.SetLength(LH, ScalarBytes * 2);
  LD.BlockUpdate(ASk, ASkOff, SecretKeySize);
  LD.OutputFinal(LH, 0, System.Length(LH));

  System.SetLength(LS, ScalarBytes);
  PruneScalar(LH, 0, LS);

  ImplSign(LD, LH, LS, APk, APkOff, ACtx, APhflag, AM, AMOff, AMLen, ASig, ASigOff);
end;

function TEd448.ImplVerify(const ASig: TCryptoLibByteArray; ASigOff: Int32;
  const APk: TCryptoLibByteArray; APkOff: Int32; const ACtx: TCryptoLibByteArray;
  APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
var
  LR, LS, LA: TCryptoLibByteArray;
  LNS, LNA: TCryptoLibUInt32Array;
  LPR, LPA: TPointAffine;
  LD: IXof;
  LH, LK: TCryptoLibByteArray;
  LV0, LV1: TCryptoLibUInt32Array;
  LPZ: TPointProjective;
begin
  if not CheckContextVar(ACtx) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);

  LR := CopyBytes(ASig, ASigOff, PointBytes);
  LS := CopyBytes(ASig, ASigOff + PointBytes, ScalarBytes);
  LA := CopyBytes(APk, APkOff, PublicKeySize);

  if not CheckPointVar(LR) then
  begin
    Result := False;
    Exit;
  end;

  System.SetLength(LNS, ScalarUints);
  if not TScalar448.CheckVar(LS, LNS) then
  begin
    Result := False;
    Exit;
  end;

  if not CheckPointFullVar(LA) then
  begin
    Result := False;
    Exit;
  end;

  InitPointAffine(LPR);
  if not DecodePointVar(LR, True, LPR) then
  begin
    Result := False;
    Exit;
  end;

  InitPointAffine(LPA);
  if not DecodePointVar(LA, True, LPA) then
  begin
    Result := False;
    Exit;
  end;

  LD := CreateAndValidateXof();
  System.SetLength(LH, ScalarBytes * 2);

  Dom4(LD, APhflag, ACtx);
  LD.BlockUpdate(LR, 0, PointBytes);
  LD.BlockUpdate(LA, 0, PointBytes);
  LD.BlockUpdate(AM, AMOff, AMLen);
  LD.OutputFinal(LH, 0, System.Length(LH));

  LK := TScalar448.Reduce912(LH);

  System.SetLength(LNA, ScalarUints);
  TScalar448.Decode(LK, LNA);

  System.SetLength(LV0, 8);
  System.SetLength(LV1, 8);

  if not TScalar448.ReduceBasisVar(LNA, LV0, LV1) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);

  TScalar448.Multiply225Var(LNS, LV1, LNS);

  InitPointProjective(LPZ);
  ScalarMultStraus225Var(LNS, LV0, LPA, LV1, LPR, LPZ);
  Result := NormalizeToNeutralElementVar(LPZ);
end;

function TEd448.ImplVerify(const ASig: TCryptoLibByteArray; ASigOff: Int32;
  const APublicPoint: IPublicPoint; const ACtx: TCryptoLibByteArray; APhflag: Byte;
  const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
var
  LR, LS, LA: TCryptoLibByteArray;
  LNS, LNA: TCryptoLibUInt32Array;
  LPR, LPA: TPointAffine;
  LD: IXof;
  LH, LK: TCryptoLibByteArray;
  LV0, LV1: TCryptoLibUInt32Array;
  LPZ: TPointProjective;
begin
  if not CheckContextVar(ACtx) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);

  LR := CopyBytes(ASig, ASigOff, PointBytes);
  LS := CopyBytes(ASig, ASigOff + PointBytes, ScalarBytes);

  if not CheckPointVar(LR) then
  begin
    Result := False;
    Exit;
  end;

  System.SetLength(LNS, ScalarUints);
  if not TScalar448.CheckVar(LS, LNS) then
  begin
    Result := False;
    Exit;
  end;

  InitPointAffine(LPR);
  if not DecodePointVar(LR, True, LPR) then
  begin
    Result := False;
    Exit;
  end;

  InitPointAffine(LPA);
  TX448Field.Negate(APublicPoint.Data, LPA.X);
  TX448Field.Copy(APublicPoint.Data, TX448Field.Size, LPA.Y, 0);

  System.SetLength(LA, PublicKeySize);
  EncodePublicPoint(APublicPoint, LA, 0);

  LD := CreateAndValidateXof();
  System.SetLength(LH, ScalarBytes * 2);

  Dom4(LD, APhflag, ACtx);
  LD.BlockUpdate(LR, 0, PointBytes);
  LD.BlockUpdate(LA, 0, PointBytes);
  LD.BlockUpdate(AM, AMOff, AMLen);
  LD.OutputFinal(LH, 0, System.Length(LH));

  LK := TScalar448.Reduce912(LH);

  System.SetLength(LNA, ScalarUints);
  TScalar448.Decode(LK, LNA);

  System.SetLength(LV0, 8);
  System.SetLength(LV1, 8);

  if not TScalar448.ReduceBasisVar(LNA, LV0, LV1) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);

  TScalar448.Multiply225Var(LNS, LV1, LNS);

  InitPointProjective(LPZ);
  ScalarMultStraus225Var(LNS, LV0, LPA, LV1, LPR, LPZ);
  Result := NormalizeToNeutralElementVar(LPZ);
end;

procedure TEd448.GeneratePrivateKey(const ARandom: ISecureRandom; const AK: TCryptoLibByteArray);
begin
  if System.Length(AK) <> SecretKeySize then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  ARandom.NextBytes(AK);
end;

procedure TEd448.GeneratePublicKey(const ASk: TCryptoLibByteArray; ASkOff: Int32;
  APk: TCryptoLibByteArray; APkOff: Int32);
var
  LD: IXof;
  LH, LS: TCryptoLibByteArray;
begin
  LD := CreateAndValidateXof();
  System.SetLength(LH, ScalarBytes * 2);
  LD.BlockUpdate(ASk, ASkOff, SecretKeySize);
  LD.OutputFinal(LH, 0, System.Length(LH));

  System.SetLength(LS, ScalarBytes);
  PruneScalar(LH, 0, LS);
  ScalarMultBaseEncoded(LS, APk, APkOff);
end;

function TEd448.GeneratePublicKey(const ASk: TCryptoLibByteArray; ASkOff: Int32): IPublicPoint;
var
  LD: IXof;
  LH, LS: TCryptoLibByteArray;
  LP: TPointProjective;
  LQ: TPointAffine;
begin
  LD := CreateAndValidateXof();
  System.SetLength(LH, ScalarBytes * 2);
  LD.BlockUpdate(ASk, ASkOff, SecretKeySize);
  LD.OutputFinal(LH, 0, System.Length(LH));

  System.SetLength(LS, ScalarBytes);
  PruneScalar(LH, 0, LS);

  InitPointProjective(LP);
  ScalarMultBase(LS, LP);

  InitPointAffine(LQ);
  NormalizeToAffine(LP, LQ);

  if 0 = CheckPoint(LQ) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);

  Result := ExportPoint(LQ);
end;

procedure TEd448.Sign(const ASk: TCryptoLibByteArray; ASkOff: Int32; const ACtx: TCryptoLibByteArray;
  const AM: TCryptoLibByteArray; AMOff, AMLen: Int32; ASig: TCryptoLibByteArray; ASigOff: Int32);
begin
  ImplSign(ASk, ASkOff, ACtx, $00, AM, AMOff, AMLen, ASig, ASigOff);
end;

procedure TEd448.Sign(const ASk: TCryptoLibByteArray; ASkOff: Int32; const APk: TCryptoLibByteArray;
  APkOff: Int32; const ACtx: TCryptoLibByteArray; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
  ASig: TCryptoLibByteArray; ASigOff: Int32);
begin
  ImplSign(ASk, ASkOff, APk, APkOff, ACtx, $00, AM, AMOff, AMLen, ASig, ASigOff);
end;

procedure TEd448.SignPrehash(const ASk: TCryptoLibByteArray; ASkOff: Int32;
  const ACtx: TCryptoLibByteArray; const APh: TCryptoLibByteArray; APhOff: Int32;
  ASig: TCryptoLibByteArray; ASigOff: Int32);
begin
  ImplSign(ASk, ASkOff, ACtx, $01, APh, APhOff, PrehashSize, ASig, ASigOff);
end;

procedure TEd448.SignPrehash(const ASk: TCryptoLibByteArray; ASkOff: Int32;
  const APk: TCryptoLibByteArray; APkOff: Int32; const ACtx: TCryptoLibByteArray;
  const APh: TCryptoLibByteArray; APhOff: Int32; ASig: TCryptoLibByteArray; ASigOff: Int32);
begin
  ImplSign(ASk, ASkOff, APk, APkOff, ACtx, $01, APh, APhOff, PrehashSize, ASig, ASigOff);
end;

procedure TEd448.SignPrehash(const ASk: TCryptoLibByteArray; ASkOff: Int32;
  const ACtx: TCryptoLibByteArray; const APh: IXof; ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LM: TCryptoLibByteArray;
begin
  System.SetLength(LM, PrehashSize);
  if PrehashSize <> APh.OutputFinal(LM, 0, PrehashSize) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPh);
  ImplSign(ASk, ASkOff, ACtx, $01, LM, 0, System.Length(LM), ASig, ASigOff);
end;

procedure TEd448.SignPrehash(const ASk: TCryptoLibByteArray; ASkOff: Int32;
  const APk: TCryptoLibByteArray; APkOff: Int32; const ACtx: TCryptoLibByteArray;
  const APh: IXof; ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LM: TCryptoLibByteArray;
begin
  System.SetLength(LM, PrehashSize);
  if PrehashSize <> APh.OutputFinal(LM, 0, PrehashSize) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPh);
  ImplSign(ASk, ASkOff, APk, APkOff, ACtx, $01, LM, 0, System.Length(LM), ASig, ASigOff);
end;

class function TEd448.ValidatePublicKeyFull(const APk: TCryptoLibByteArray; APkOff: Int32): Boolean;
var
  LA: TCryptoLibByteArray;
  LPA: TPointAffine;
begin
  LA := CopyBytes(APk, APkOff, PublicKeySize);

  if not CheckPointFullVar(LA) then
  begin
    Result := False;
    Exit;
  end;

  InitPointAffine(LPA);
  if not DecodePointVar(LA, False, LPA) then
  begin
    Result := False;
    Exit;
  end;

  Result := CheckPointOrderVar(LPA);
end;

class function TEd448.ValidatePublicKeyFullExport(const APk: TCryptoLibByteArray; APkOff: Int32): IPublicPoint;
var
  LA: TCryptoLibByteArray;
  LPA: TPointAffine;
begin
  LA := CopyBytes(APk, APkOff, PublicKeySize);

  if not CheckPointFullVar(LA) then
  begin
    Result := nil;
    Exit;
  end;

  InitPointAffine(LPA);
  if not DecodePointVar(LA, False, LPA) then
  begin
    Result := nil;
    Exit;
  end;

  if not CheckPointOrderVar(LPA) then
  begin
    Result := nil;
    Exit;
  end;

  Result := ExportPoint(LPA);
end;

class function TEd448.ValidatePublicKeyPartial(const APk: TCryptoLibByteArray; APkOff: Int32): Boolean;
var
  LA: TCryptoLibByteArray;
  LPA: TPointAffine;
begin
  LA := CopyBytes(APk, APkOff, PublicKeySize);

  if not CheckPointFullVar(LA) then
  begin
    Result := False;
    Exit;
  end;

  InitPointAffine(LPA);
  Result := DecodePointVar(LA, False, LPA);
end;

class function TEd448.ValidatePublicKeyPartialExport(const APk: TCryptoLibByteArray; APkOff: Int32): IPublicPoint;
var
  LA: TCryptoLibByteArray;
  LPA: TPointAffine;
begin
  LA := CopyBytes(APk, APkOff, PublicKeySize);

  if not CheckPointFullVar(LA) then
  begin
    Result := nil;
    Exit;
  end;

  InitPointAffine(LPA);
  if not DecodePointVar(LA, False, LPA) then
  begin
    Result := nil;
    Exit;
  end;

  Result := ExportPoint(LPA);
end;

function TEd448.Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray;
  APkOff: Int32; const ACtx: TCryptoLibByteArray; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
begin
  Result := ImplVerify(ASig, ASigOff, APk, APkOff, ACtx, $00, AM, AMOff, AMLen);
end;

function TEd448.Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
  const ACtx: TCryptoLibByteArray; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
begin
  Result := ImplVerify(ASig, ASigOff, APublicPoint, ACtx, $00, AM, AMOff, AMLen);
end;

function TEd448.VerifyPrehash(const ASig: TCryptoLibByteArray; ASigOff: Int32;
  const APk: TCryptoLibByteArray; APkOff: Int32; const ACtx: TCryptoLibByteArray;
  const APh: TCryptoLibByteArray; APhOff: Int32): Boolean;
begin
  Result := ImplVerify(ASig, ASigOff, APk, APkOff, ACtx, $01, APh, APhOff, PrehashSize);
end;

function TEd448.VerifyPrehash(const ASig: TCryptoLibByteArray; ASigOff: Int32;
  const APublicPoint: IPublicPoint; const ACtx: TCryptoLibByteArray;
  const APh: TCryptoLibByteArray; APhOff: Int32): Boolean;
begin
  Result := ImplVerify(ASig, ASigOff, APublicPoint, ACtx, $01, APh, APhOff, PrehashSize);
end;

function TEd448.VerifyPrehash(const ASig: TCryptoLibByteArray; ASigOff: Int32;
  const APk: TCryptoLibByteArray; APkOff: Int32; const ACtx: TCryptoLibByteArray; const APh: IXof): Boolean;
var
  LM: TCryptoLibByteArray;
begin
  System.SetLength(LM, PrehashSize);
  if PrehashSize <> APh.OutputFinal(LM, 0, PrehashSize) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPh);
  Result := ImplVerify(ASig, ASigOff, APk, APkOff, ACtx, $01, LM, 0, System.Length(LM));
end;

function TEd448.VerifyPrehash(const ASig: TCryptoLibByteArray; ASigOff: Int32;
  const APublicPoint: IPublicPoint; const ACtx: TCryptoLibByteArray; const APh: IXof): Boolean;
var
  LM: TCryptoLibByteArray;
begin
  System.SetLength(LM, PrehashSize);
  if PrehashSize <> APh.OutputFinal(LM, 0, PrehashSize) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPh);
  Result := ImplVerify(ASig, ASigOff, APublicPoint, ACtx, $01, LM, 0, System.Length(LM));
end;

end.
