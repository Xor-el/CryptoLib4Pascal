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

unit ClpEd25519;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  ClpCodec,
  ClpDigestUtilities,
  ClpBitOperations,
  ClpIDigest,
  ClpISecureRandom,
  ClpNat256,
  ClpScalar25519,
  ClpWnaf,
  ClpX25519Field,
  ClpInterleave,
  ClpCryptoLibTypes;

resourcestring
  SDigestSize = 'Digest must produce 64 bytes';
  SInvalidOp = 'Invalid point';
  SInvalidCtx = 'ctx';

type
  /// <summary>
  /// A low-level implementation of the Ed25519, Ed25519ctx, and Ed25519ph instantiations of the Edwards-Curve Digital
  /// Signature Algorithm specified in <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>.
  /// </summary>
  /// <remarks>
  /// The implementation strategy is mostly drawn from <a href="https://ia.cr/2012/309">
  /// Mike Hamburg, "Fast and compact elliptic-curve cryptography"</a>, notably the "signed multi-comb" algorithm (for
  /// scalar multiplication by a fixed point), the "half Niels coordinates" (for precomputed points), and the
  /// "extensible coordinates" (for accumulators). Standard
  /// <a href="https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html">extended coordinates</a> are used during
  /// precomputations, needing only a single extra point addition formula.
  /// </remarks>
  TEd25519 = class(TObject)
  strict private
  type
    TPointAccum = record
    private
      Fx, Fy, Fz, Fu, Fv: TCryptoLibInt32Array;
    public
      property X: TCryptoLibInt32Array read Fx write Fx;
      property Y: TCryptoLibInt32Array read Fy write Fy;
      property Z: TCryptoLibInt32Array read Fz write Fz;
      property U: TCryptoLibInt32Array read Fu write Fu;
      property V: TCryptoLibInt32Array read Fv write Fv;
    end;

    TPointAffine = record
    private
      Fx, Fy: TCryptoLibInt32Array;
    public
      property X: TCryptoLibInt32Array read Fx write Fx;
      property Y: TCryptoLibInt32Array read Fy write Fy;
    end;

    TPointExtended = record
    private
      Fx, Fy, Fz, Ft: TCryptoLibInt32Array;
    public
      property X: TCryptoLibInt32Array read Fx write Fx;
      property Y: TCryptoLibInt32Array read Fy write Fy;
      property Z: TCryptoLibInt32Array read Fz write Fz;
      property T: TCryptoLibInt32Array read Ft write Ft;
    end;

    TPointPrecomp = record
    private
      Fymx_h, Fypx_h, Fxyd: TCryptoLibInt32Array;
    public
      property YmxH: TCryptoLibInt32Array read Fymx_h write Fymx_h;
      property YpxH: TCryptoLibInt32Array read Fypx_h write Fypx_h;
      property Xyd: TCryptoLibInt32Array read Fxyd write Fxyd;
    end;

    TPointPrecompZ = record
    private
      Fymx_h, Fypx_h, Fxyd, Fz: TCryptoLibInt32Array;
    public
      property YmxH: TCryptoLibInt32Array read Fymx_h write Fymx_h;
      property YpxH: TCryptoLibInt32Array read Fypx_h write Fypx_h;
      property Xyd: TCryptoLibInt32Array read Fxyd write Fxyd;
      property Z: TCryptoLibInt32Array read Fz write Fz;
    end;

    TPointTemp = record
    private
      Fr0, Fr1: TCryptoLibInt32Array;
    public
      property R0: TCryptoLibInt32Array read Fr0 write Fr0;
      property R1: TCryptoLibInt32Array read Fr1 write Fr1;
    end;

  public
   type
    TAlgorithm = (Ed25519, Ed25519ctx, Ed25519ph);

    IPublicPoint = interface
      ['{8B8C3F2A-1D4E-4A5B-9C6D-7E8F0A1B2C3D}']
      function GetData: TCryptoLibInt32Array;

      property Data: TCryptoLibInt32Array read GetData;
    end;

    TPublicPoint = class sealed(TInterfacedObject, IPublicPoint)
    strict private
      FData: TCryptoLibInt32Array;
      function GetData: TCryptoLibInt32Array;
    public
      constructor Create(const AData: TCryptoLibInt32Array);
      property Data: TCryptoLibInt32Array read GetData;
    end;

  strict private
  const
    CoordUints = 8;
    PointBytes = CoordUints * 4;
    ScalarUints = 8;
    ScalarBytes = ScalarUints * 4;
    WnafWidth128 = 4;
    WnafWidthBase = 6;
    PrecompBlocks = 8;
    PrecompTeeth = 4;
    PrecompSpacing = 8;
    PrecompRange = PrecompBlocks * PrecompTeeth * PrecompSpacing;
    PrecompPoints = 1 shl (PrecompTeeth - 1);
    PrecompMask = PrecompPoints - 1;
  class var
    FDom2Prefix: TCryptoLibByteArray;
    FP: TCryptoLibUInt32Array;
    FOrder8_y1, FOrder8_y2: TCryptoLibUInt32Array;
    FB_x, FB_y, FB128_x, FB128_y: TCryptoLibInt32Array;
    FC_d, FC_d2, FC_d4: TCryptoLibInt32Array;
    FPrecompLock: TCriticalSection;
    FPrecompBaseWnaf: TCryptoLibGenericArray<TPointPrecomp>;
    FPrecompBase128Wnaf: TCryptoLibGenericArray<TPointPrecomp>;
    FPrecompBaseComb: TCryptoLibInt32Array;
  class procedure Boot; static;
  class constructor Create;
  class destructor Destroy;
  class function CalculateS(const AR, AK, &AS: TCryptoLibByteArray): TCryptoLibByteArray; static;
  class function CheckContextVar(ACtx: TCryptoLibByteArray; APhflag: Byte): Boolean; static;
  class function CheckPoint(const AP: TPointAccum): Int32; overload; static;
  class function CheckPoint(const AP: TPointAffine): Int32; overload; static;
  class function CheckPointOrderVar(var AP: TPointAffine): Boolean; static;
  class function CheckPointFullVar(const AP: TCryptoLibByteArray): Boolean; static;
  class function CheckPointVar(const AP: TCryptoLibByteArray): Boolean; static;
  class procedure CopyBytes(const ABuf: TCryptoLibByteArray; AOff: Int32; ALen: Int32; var AOut: TCryptoLibByteArray); static;
  class function CreateDigest(): IDigest; static;
  class function DecodePointVar(const AP: TCryptoLibByteArray; ANegate: Boolean; var AR: TPointAffine): Boolean; static;
  class procedure Dom2(const AD: IDigest; APhflag: Byte; const ACtx: TCryptoLibByteArray); static;
  class procedure EncodePoint(const AP: TPointAffine; AR: TCryptoLibByteArray; AROff: Int32); static;
  class function EncodeResult(var AP: TPointAccum; AR: TCryptoLibByteArray; AROff: Int32): Int32; static;
  class function GetWindow4(const AX: TCryptoLibUInt32Array; AN: Int32): UInt32; static;
  class procedure GroupCombBits(AN: TCryptoLibUInt32Array); static;
  class procedure ImplSign(const AD: IDigest; AH, &AS, APk: TCryptoLibByteArray; APkOff: Int32;
    const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
    ASig: TCryptoLibByteArray; ASigOff: Int32); overload; static;
  class function ImplVerify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
    const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload; static;
  class procedure InitPointAccum(var AR: TPointAccum); static;
  class procedure InitPointAffine(var AR: TPointAffine); static;
  class procedure InitPointExtended(var AR: TPointExtended); static;
  class procedure InitPointPrecomp(var AR: TPointPrecomp); static;
  class procedure InitPointPrecompZ(var AR: TPointPrecompZ); static;
  class procedure InitPointTemp(var AR: TPointTemp); static;
  class procedure InvertDoubleZs(APoints: TCryptoLibGenericArray<TPointExtended>); static;
  class function NormalizeToNeutralElementVar(var AP: TPointAccum): Boolean; static;
  class procedure NormalizeToAffine(var AP: TPointAccum; var AR: TPointAffine); static;
  class procedure PointAdd(const AP, AQ: TPointExtended; var AR: TPointExtended; var AT: TPointTemp); overload; static;
  class procedure PointAdd(const AP: TPointPrecomp; var AR: TPointAccum; var AT: TPointTemp); overload; static;
  class procedure PointAdd(const AP: TPointPrecompZ; var AR: TPointAccum; var AT: TPointTemp); overload; static;
  class procedure PointAddVar(ANegate: Boolean; const AP: TPointPrecomp; var AR: TPointAccum; var AT: TPointTemp); overload; static;
  class procedure PointAddVar(ANegate: Boolean; const AP: TPointPrecompZ; var AR: TPointAccum; var AT: TPointTemp); overload; static;
  class procedure PointCopy(const AP: TPointAccum; var AR: TPointExtended); overload; static;
  class procedure PointCopy(const AP: TPointAffine; var AR: TPointExtended); overload; static;
  class procedure PointCopy(const AP: TPointExtended; var AR: TPointPrecompZ); overload; static;
  class procedure PointDouble(var AR: TPointAccum); static;
  class procedure PointLookup(ABlock, AIndex: Int32; var AP: TPointPrecomp); static;
  class procedure PointLookupZ(const AX: TCryptoLibUInt32Array; AN: Int32; const ATable: TCryptoLibInt32Array; var AR: TPointPrecompZ); static;
  class procedure PointPrecompute(const AP: TPointAffine; var APoints: TCryptoLibGenericArray<TPointExtended>; APointsOff, APointsLen: Int32; var AT: TPointTemp); static;
  class function PointPrecomputeZ(const AP: TPointAffine; ACount: Int32; var AT: TPointTemp): TCryptoLibInt32Array; overload; static;
  class procedure PointPrecomputeZ(const AP: TPointAffine; var APoints: TCryptoLibGenericArray<TPointPrecompZ>; ACount: Int32; var AT: TPointTemp); overload; static;
  class procedure PointSetNeutral(var AP: TPointAccum); static;
  class procedure PruneScalar(const AN: TCryptoLibByteArray; ANOff: Int32; AR: TCryptoLibByteArray); static;
  class procedure ScalarMult(const AK: TCryptoLibByteArray; const AP: TPointAffine; var AR: TPointAccum); static;
  class procedure ScalarMultBase(const AK: TCryptoLibByteArray; var AR: TPointAccum); static;
  class procedure ScalarMultBaseEncoded(const AK: TCryptoLibByteArray; AR: TCryptoLibByteArray; AROff: Int32); static;
  class procedure ScalarMultOrderVar(const AP: TPointAffine; var AR: TPointAccum); static;
  class procedure ScalarMultStraus128Var(const ANb: TCryptoLibUInt32Array; const ANp: TCryptoLibUInt32Array; const AP: TPointAffine;
    const ANq: TCryptoLibUInt32Array; const AQ: TPointAffine; var AR: TPointAccum); static;
  class function ExportPoint(var AP: TPointAffine): IPublicPoint; static;
  class function ImplVerify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
    const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload; static;
  class procedure ImplSign(const &AS: TCryptoLibByteArray; ASOff: Int32; const ACtx: TCryptoLibByteArray; APhflag: Byte;
    const AM: TCryptoLibByteArray; AMOff: Int32; AMLen: Int32; const ASig: TCryptoLibByteArray; ASigOff: Int32); overload; static;
  class procedure ImplSign(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
    const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff: Int32; AMLen: Int32;
    const ASig: TCryptoLibByteArray; ASigOff: Int32); overload; static;
  public
    const
    PrehashSize = 64;
    PublicKeySize = PointBytes;
    SecretKeySize = 32;
    SignatureSize = PointBytes + ScalarBytes;

    class procedure Precompute; static;
    class procedure ScalarMultBaseYZ(const AK: TCryptoLibByteArray; AKOff: Int32; AY, AZ: TCryptoLibInt32Array); static;

    class procedure EncodePublicPoint(const APublicPoint: IPublicPoint; APk: TCryptoLibByteArray; APkOff: Int32); static;
    class function GeneratePublicKey(const &AS: TCryptoLibByteArray; ASOff: Int32): IPublicPoint; overload; static;
    class function ValidatePublicKeyFull(const APk: TCryptoLibByteArray; APkOff: Int32): Boolean; static;
    class function ValidatePublicKeyFullExport(const APk: TCryptoLibByteArray; APkOff: Int32): IPublicPoint; static;
    class function ValidatePublicKeyPartial(const APk: TCryptoLibByteArray; APkOff: Int32): Boolean; static;
    class function ValidatePublicKeyPartialExport(const APk: TCryptoLibByteArray; APkOff: Int32): IPublicPoint; static;
    class function CreatePreHash(): IDigest; static;

    function GetAlgorithmName: String;
    procedure GeneratePrivateKey(const ARandom: ISecureRandom; const AK: TCryptoLibByteArray);
    procedure GeneratePublicKey(const &AS: TCryptoLibByteArray; ASOff: Int32; APk: TCryptoLibByteArray; APkOff: Int32); overload;
    procedure Sign(const &AS: TCryptoLibByteArray; ASOff: Int32; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
    procedure Sign(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
      const AM: TCryptoLibByteArray; AMOff, AMLen: Int32; const ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
    procedure Sign(const &AS: TCryptoLibByteArray; ASOff: Int32; const ACtx, AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
    procedure Sign(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
      const ACtx, AM: TCryptoLibByteArray; AMOff, AMLen: Int32; const ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
    procedure SignPreHash(const &AS: TCryptoLibByteArray; ASOff: Int32; const ACtx, APh: TCryptoLibByteArray; APhOff: Int32;
      const ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
    procedure SignPreHash(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
      const ACtx, APh: TCryptoLibByteArray; APhOff: Int32; const ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
    procedure SignPreHash(const &AS: TCryptoLibByteArray; ASOff: Int32; const ACtx: TCryptoLibByteArray; const APh: IDigest;
      const ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
    procedure SignPreHash(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
      const ACtx: TCryptoLibByteArray; const APh: IDigest; const ASig: TCryptoLibByteArray; ASigOff: Int32); overload;
    function Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
      const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload;
    function Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
      const ACtx, AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload;
    function Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
      const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload;
    function Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
      const ACtx, AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean; overload;
    function VerifyPreHash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
      const ACtx, APh: TCryptoLibByteArray; APhOff: Int32): Boolean; overload;
    function VerifyPreHash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
      const ACtx: TCryptoLibByteArray; const APh: IDigest): Boolean; overload;
    function VerifyPreHash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
      const ACtx, APh: TCryptoLibByteArray; APhOff: Int32): Boolean; overload;
    function VerifyPreHash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
      const ACtx: TCryptoLibByteArray; const APh: IDigest): Boolean; overload;
  end;

implementation

{ TEd25519.TPublicPoint }

constructor TEd25519.TPublicPoint.Create(const AData: TCryptoLibInt32Array);
begin
  Inherited Create;
  FData := AData;
end;

function TEd25519.TPublicPoint.GetData: TCryptoLibInt32Array;
begin
  Result := FData;
end;

{ TEd25519 }

class constructor TEd25519.Create;
begin
  Boot;
end;

class procedure TEd25519.Boot;
begin
  FDom2Prefix := TCryptoLibByteArray.Create($53, $69, $67, $45, $64, $32, $35, $35, $31, $39, $20,
    $6E, $6F, $20, $45, $64, $32, $35, $35, $31, $39, $20, $63, $6F, $6C, $6C, $69, $73, $69,
    $6F, $6E, $73);
  FP := TCryptoLibUInt32Array.Create($FFFFFFED, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $7FFFFFFF);
  FOrder8_y1 := TCryptoLibUInt32Array.Create($706A17C7, $4FD84D3D, $760B3CBA, $0F67100D, $FA53202A,
    $C6CC392C, $77FDC74E, $7A03AC92);
  FOrder8_y2 := TCryptoLibUInt32Array.Create($8F95E826, $B027B2C2, $89F4C345, $F098EFF2, $05ACDFD5,
    $3933C6D3, $880238B1, $05FC536D);
  FB_x := TCryptoLibInt32Array.Create($0325D51A, $018B5823, $007B2C95, $0304A92D, $00D2598E, $01D6DC5C,
    $01388C7F, $013FEC0A, $029E6B72, $0042D26D);
  FB_y := TCryptoLibInt32Array.Create($02666658, $01999999, $00666666, $03333333, $00CCCCCC, $02666666,
    $01999999, $00666666, $03333333, $00CCCCCC);
  FB128_x := TCryptoLibInt32Array.Create($00B7E824, $0011EB98, $003E5FC8, $024E1739, $0131CD0B, $014E29A0,
    $034E6138, $0132C952, $03F9E22F, $00984F5F);
  FB128_y := TCryptoLibInt32Array.Create($03F5A66B, $02AF4452, $0049E5BB, $00F28D26, $0121A17C, $02C29C3A,
    $0047AD89, $0087D95F, $0332936E, $00BE5933);
  FC_d := TCryptoLibInt32Array.Create($035978A3, $02D37284, $018AB75E, $026A0A0E, $0000E014, $0379E898,
    $01D01E5D, $01E738CC, $03715B7F, $00A406D9);
  FC_d2 := TCryptoLibInt32Array.Create($02B2F159, $01A6E509, $01156EBD, $00D4141D, $0001C029, $02F3D130,
    $03A03CBB, $01CE7198, $02E2B6FF, $00480DB3);
  FC_d4 := TCryptoLibInt32Array.Create($0165E2B2, $034DCA13, $002ADD7A, $01A8283B, $00038052, $01E7A260,
    $03407977, $019CE331, $01C56DFF, $00901B67);
  FPrecompLock := TCriticalSection.Create;
end;

class destructor TEd25519.Destroy;
begin
  FPrecompLock.Free;
  FPrecompLock := nil;
end;

class function TEd25519.CalculateS(const AR, AK, &AS: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LT: TCryptoLibUInt32Array;
  LU, LV: TCryptoLibUInt32Array;
  LResult: TCryptoLibByteArray;
begin
  System.SetLength(LT, ScalarUints * 2);
  System.SetLength(LU, ScalarUints);
  System.SetLength(LV, ScalarUints);
  TScalar25519.Decode(AR, LT);
  TScalar25519.Decode(AK, LU);
  TScalar25519.Decode(&AS, LV);
  TNat256.MulAddTo(LU, LV, LT);
  System.SetLength(LResult, ScalarBytes * 2);
  TCodec.Encode32(LT, 0, System.Length(LT), LResult, 0);
  Result := TScalar25519.Reduce512(LResult);
end;

class function TEd25519.CheckContextVar(ACtx: TCryptoLibByteArray; APhflag: Byte): Boolean;
begin
  Result := ((ACtx = nil) and (APhflag = $00)) or ((ACtx <> nil) and (System.Length(ACtx) < 256))
    or ((APhflag = $01) and (ACtx = nil));
end;

class function TEd25519.CheckPoint(const AP: TPointAccum): Int32;
var
  LT, LU, LV, LW: TCryptoLibInt32Array;
begin
  LT := TX25519Field.Create;
  LU := TX25519Field.Create;
  LV := TX25519Field.Create;
  LW := TX25519Field.Create;
  TX25519Field.Sqr(AP.X, LU);
  TX25519Field.Sqr(AP.Y, LV);
  TX25519Field.Sqr(AP.Z, LW);
  TX25519Field.Mul(LU, LV, LT);
  TX25519Field.Sub(LU, LV, LU);
  TX25519Field.Mul(LU, LW, LU);
  TX25519Field.Sqr(LW, LW);
  TX25519Field.Mul(LT, FC_d, LT);
  TX25519Field.Add(LT, LW, LT);
  TX25519Field.Add(LT, LU, LT);
  TX25519Field.Normalize(LT);
  TX25519Field.Normalize(LV);
  TX25519Field.Normalize(LW);
  Result := TX25519Field.IsZero(LT) and (not TX25519Field.IsZero(LV)) and (not TX25519Field.IsZero(LW));
end;

class function TEd25519.CheckPoint(const AP: TPointAffine): Int32;
var
  LT, LU, LV: TCryptoLibInt32Array;
begin
  LT := TX25519Field.Create;
  LU := TX25519Field.Create;
  LV := TX25519Field.Create;
  TX25519Field.Sqr(AP.X, LU);
  TX25519Field.Sqr(AP.Y, LV);
  TX25519Field.Mul(LU, LV, LT);
  TX25519Field.Sub(LU, LV, LU);
  TX25519Field.Mul(LT, FC_d, LT);
  TX25519Field.AddOne(LT);
  TX25519Field.Add(LT, LU, LT);
  TX25519Field.Normalize(LT);
  TX25519Field.Normalize(LV);
  Result := TX25519Field.IsZero(LT) and (not TX25519Field.IsZero(LV));
end;

class function TEd25519.CheckPointFullVar(const AP: TCryptoLibByteArray): Boolean;
var
  LY7, LT0, LT1, LT2, LT3, LYI, LY0: UInt32;
  LI: Int32;
begin
  LY7 := TCodec.Decode32(AP, 28) and $7FFFFFFF;
  LT0 := LY7;
  LT1 := LY7 xor FP[7];
  LT2 := LY7 xor FOrder8_y1[7];
  LT3 := LY7 xor FOrder8_y2[7];
  LI := CoordUints - 2;
  while LI > 0 do
  begin
    LYI := TCodec.Decode32(AP, LI * 4);
    LT0 := LT0 or LYI;
    LT1 := LT1 or (LYI xor FP[LI]);
    LT2 := LT2 or (LYI xor FOrder8_y1[LI]);
    LT3 := LT3 or (LYI xor FOrder8_y2[LI]);
    System.Dec(LI);
  end;
  LY0 := TCodec.Decode32(AP, 0);
  if (LT0 = 0) and (LY0 <= 1) then
    Exit(False);
  if (LT1 = 0) and (LY0 >= FP[0] - 1) then
    Exit(False);
  LT2 := LT2 or (LY0 xor FOrder8_y1[0]);
  LT3 := LT3 or (LY0 xor FOrder8_y2[0]);
  Result := (LT2 <> 0) and (LT3 <> 0);
end;

class function TEd25519.CheckPointVar(const AP: TCryptoLibByteArray): Boolean;
var
  LI: Int32;
begin
  if (TCodec.Decode32(AP, 28) and $7FFFFFFF) < FP[7] then
    Exit(True);
  LI := CoordUints - 2;
  while LI >= 0 do
  begin
    if TCodec.Decode32(AP, LI * 4) < FP[LI] then
      Exit(True);
    System.Dec(LI);
  end;
  Result := False;
end;

class procedure TEd25519.CopyBytes(const ABuf: TCryptoLibByteArray; AOff: Int32; ALen: Int32; var AOut: TCryptoLibByteArray);
begin
  System.SetLength(AOut, ALen);
  if ALen > 0 then
    System.Move(ABuf[AOff], AOut[0], ALen);
end;

class function TEd25519.CreateDigest(): IDigest;
var
  LD: IDigest;
begin
  LD := TDigestUtilities.GetDigest('SHA-512');
  if LD.GetDigestSize() <> 64 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SDigestSize);
  Result := LD;
end;

class function TEd25519.DecodePointVar(const AP: TCryptoLibByteArray; ANegate: Boolean; var AR: TPointAffine): Boolean;
var
  LX0: Int32;
  LU, LV: TCryptoLibInt32Array;
begin
  LX0 := TBitOperations.Asr32(Int32(AP[PointBytes - 1] and $80), 7);
  TX25519Field.Decode(AP, AR.Y);
  LU := TX25519Field.Create;
  LV := TX25519Field.Create;
  TX25519Field.Sqr(AR.Y, LU);
  TX25519Field.Mul(FC_d, LU, LV);
  TX25519Field.SubOne(LU);
  TX25519Field.AddOne(LV);
  if not TX25519Field.SqrtRatioVar(LU, LV, AR.X) then
    Exit(False);
  TX25519Field.Normalize(AR.X);
  if (LX0 = 1) and TX25519Field.IsZeroVar(AR.X) then
    Exit(False);
  if ANegate xor (LX0 <> (AR.X[0] and 1)) then
  begin
    TX25519Field.Negate(AR.X, AR.X);
    TX25519Field.Normalize(AR.X);
  end;
  Result := True;
end;

class procedure TEd25519.Dom2(const AD: IDigest; APhflag: Byte; const ACtx: TCryptoLibByteArray);
var
  LN, LCtxLen: Int32;
  LT: TCryptoLibByteArray;
begin
  LN := System.Length(FDom2Prefix);
  if ACtx = nil then
    LCtxLen := 0
  else
    LCtxLen := System.Length(ACtx);
  System.SetLength(LT, LN + 2 + LCtxLen);
  System.Move(FDom2Prefix[0], LT[0], LN);
  LT[LN] := APhflag;
  LT[LN + 1] := Byte(LCtxLen);
  if LCtxLen > 0 then
    System.Move(ACtx[0], LT[LN + 2], LCtxLen);
  AD.BlockUpdate(LT, 0, System.Length(LT));
end;

class procedure TEd25519.EncodePoint(const AP: TPointAffine; AR: TCryptoLibByteArray; AROff: Int32);
begin
  TX25519Field.Encode(AP.Y, AR, AROff);
  AR[AROff + PointBytes - 1] := AR[AROff + PointBytes - 1] or Byte((AP.X[0] and 1) shl 7);
end;

class function TEd25519.EncodeResult(var AP: TPointAccum; AR: TCryptoLibByteArray; AROff: Int32): Int32;
var
  LQ: TPointAffine;
begin
  InitPointAffine(LQ);
  NormalizeToAffine(AP, LQ);
  Result := CheckPoint(LQ);
  EncodePoint(LQ, AR, AROff);
end;

class function TEd25519.GetWindow4(const AX: TCryptoLibUInt32Array; AN: Int32): UInt32;
var
  LW: Int32;
  LB: Int32;
begin
  LW := UInt32(AN) shr 3;
  LB := (AN and 7) shl 2;
  Result := (AX[LW] shr LB) and 15;
end;

class procedure TEd25519.GroupCombBits(AN: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < System.Length(AN) do
  begin
    AN[LI] := TInterleave.Shuffle2(AN[LI]);
    System.Inc(LI);
  end;
end;

class procedure TEd25519.InitPointAccum(var AR: TPointAccum);
begin
  AR.X := TX25519Field.Create;
  AR.Y := TX25519Field.Create;
  AR.Z := TX25519Field.Create;
  AR.U := TX25519Field.Create;
  AR.V := TX25519Field.Create;
end;

class procedure TEd25519.InitPointAffine(var AR: TPointAffine);
begin
  AR.X := TX25519Field.Create;
  AR.Y := TX25519Field.Create;
end;

class procedure TEd25519.InitPointExtended(var AR: TPointExtended);
begin
  AR.X := TX25519Field.Create;
  AR.Y := TX25519Field.Create;
  AR.Z := TX25519Field.Create;
  AR.T := TX25519Field.Create;
end;

class procedure TEd25519.InitPointPrecomp(var AR: TPointPrecomp);
begin
  AR.YmxH := TX25519Field.Create;
  AR.YpxH := TX25519Field.Create;
  AR.Xyd := TX25519Field.Create;
end;

class procedure TEd25519.InitPointPrecompZ(var AR: TPointPrecompZ);
begin
  AR.YmxH := TX25519Field.Create;
  AR.YpxH := TX25519Field.Create;
  AR.Xyd := TX25519Field.Create;
  AR.Z := TX25519Field.Create;
end;

class procedure TEd25519.InitPointTemp(var AR: TPointTemp);
begin
  AR.R0 := TX25519Field.Create;
  AR.R1 := TX25519Field.Create;
end;

class procedure TEd25519.InvertDoubleZs(APoints: TCryptoLibGenericArray<TPointExtended>);
var
  LCount, LI, LJ: Int32;
  LCs: TCryptoLibInt32Array;
  LU, LT: TCryptoLibInt32Array;
begin
  LCount := System.Length(APoints);
  LCs := TX25519Field.CreateTable(LCount);
  LU := TX25519Field.Create;
  TX25519Field.Copy(APoints[0].Z, 0, LU, 0);
  TX25519Field.Copy(LU, 0, LCs, 0);
  LI := 0;
  System.Inc(LI);
  while LI < LCount do
  begin
    TX25519Field.Mul(LU, APoints[LI].Z, LU);
    TX25519Field.Copy(LU, 0, LCs, LI * TX25519Field.Size);
    System.Inc(LI);
  end;
  TX25519Field.Add(LU, LU, LU);
  TX25519Field.InvVar(LU, LU);
  System.Dec(LI);
  LT := TX25519Field.Create;
  while LI > 0 do
  begin
    LJ := LI;
    System.Dec(LI);
    TX25519Field.Copy(LCs, LI * TX25519Field.Size, LT, 0);
    TX25519Field.Mul(LT, LU, LT);
    TX25519Field.Mul(LU, APoints[LJ].Z, LU);
    TX25519Field.Copy(LT, 0, APoints[LJ].Z, 0);
  end;
  TX25519Field.Copy(LU, 0, APoints[0].Z, 0);
end;

class function TEd25519.NormalizeToNeutralElementVar(var AP: TPointAccum): Boolean;
begin
  TX25519Field.Normalize(AP.X);
  TX25519Field.Normalize(AP.Y);
  TX25519Field.Normalize(AP.Z);
  Result := TX25519Field.IsZeroVar(AP.X) and (not TX25519Field.IsZeroVar(AP.Y)) and TX25519Field.AreEqualVar(AP.Y, AP.Z);
end;

class procedure TEd25519.NormalizeToAffine(var AP: TPointAccum; var AR: TPointAffine);
begin
  TX25519Field.Inv(AP.Z, AR.Y);
  TX25519Field.Mul(AR.Y, AP.X, AR.X);
  TX25519Field.Mul(AR.Y, AP.Y, AR.Y);
  TX25519Field.Normalize(AR.X);
  TX25519Field.Normalize(AR.Y);
end;

class procedure TEd25519.PointAdd(const AP, AQ: TPointExtended; var AR: TPointExtended; var AT: TPointTemp);
var
  LA, LB, LC, LD, LE, LF, LG, LH: TCryptoLibInt32Array;
begin
  LA := AR.X;
  LB := AR.Y;
  LC := AT.R0;
  LD := AT.R1;
  LE := LA;
  LF := LC;
  LG := LD;
  LH := LB;
  TX25519Field.Apm(AP.Y, AP.X, LB, LA);
  TX25519Field.Apm(AQ.Y, AQ.X, LD, LC);
  TX25519Field.Mul(LA, LC, LA);
  TX25519Field.Mul(LB, LD, LB);
  TX25519Field.Mul(AP.T, AQ.T, LC);
  TX25519Field.Mul(LC, FC_d2, LC);
  TX25519Field.Add(AP.Z, AP.Z, LD);
  TX25519Field.Mul(LD, AQ.Z, LD);
  TX25519Field.Apm(LB, LA, LH, LE);
  TX25519Field.Apm(LD, LC, LG, LF);
  TX25519Field.Mul(LE, LH, AR.T);
  TX25519Field.Mul(LF, LG, AR.Z);
  TX25519Field.Mul(LE, LF, AR.X);
  TX25519Field.Mul(LH, LG, AR.Y);
end;

class procedure TEd25519.PointAdd(const AP: TPointPrecomp; var AR: TPointAccum; var AT: TPointTemp);
var
  LA, LB, LC, LE, LF, LG, LH: TCryptoLibInt32Array;
begin
  LA := AR.X;
  LB := AR.Y;
  LC := AT.R0;
  LE := AR.U;
  LF := LA;
  LG := LB;
  LH := AR.V;
  TX25519Field.Apm(AR.Y, AR.X, LB, LA);
  TX25519Field.Mul(LA, AP.YmxH, LA);
  TX25519Field.Mul(LB, AP.YpxH, LB);
  TX25519Field.Mul(AR.U, AR.V, LC);
  TX25519Field.Mul(LC, AP.Xyd, LC);
  TX25519Field.Apm(LB, LA, LH, LE);
  TX25519Field.Apm(AR.Z, LC, LG, LF);
  TX25519Field.Mul(LF, LG, AR.Z);
  TX25519Field.Mul(LF, LE, AR.X);
  TX25519Field.Mul(LG, LH, AR.Y);
end;

class procedure TEd25519.PointAdd(const AP: TPointPrecompZ; var AR: TPointAccum; var AT: TPointTemp);
var
  LA, LB, LC, LD, LE, LF, LG, LH: TCryptoLibInt32Array;
begin
  LA := AR.X;
  LB := AR.Y;
  LC := AT.R0;
  LD := AR.Z;
  LE := AR.U;
  LF := LA;
  LG := LB;
  LH := AR.V;
  TX25519Field.Apm(AR.Y, AR.X, LB, LA);
  TX25519Field.Mul(LA, AP.YmxH, LA);
  TX25519Field.Mul(LB, AP.YpxH, LB);
  TX25519Field.Mul(AR.U, AR.V, LC);
  TX25519Field.Mul(LC, AP.Xyd, LC);
  TX25519Field.Mul(AR.Z, AP.Z, LD);
  TX25519Field.Apm(LB, LA, LH, LE);
  TX25519Field.Apm(LD, LC, LG, LF);
  TX25519Field.Mul(LF, LG, AR.Z);
  TX25519Field.Mul(LF, LE, AR.X);
  TX25519Field.Mul(LG, LH, AR.Y);
end;

class procedure TEd25519.PointAddVar(ANegate: Boolean; const AP: TPointPrecomp; var AR: TPointAccum; var AT: TPointTemp);
var
  LNa, LNb, LNf, LNg: TCryptoLibInt32Array;
  LA, LB, LC, LE, LF, LG, LH: TCryptoLibInt32Array;
begin
  LA := AR.X;
  LB := AR.Y;
  LC := AT.R0;
  LE := AR.U;
  LF := LA;
  LG := LB;
  LH := AR.V;
  if ANegate then
  begin
    LNa := LB;
    LNb := LA;
  end
  else
  begin
    LNa := LA;
    LNb := LB;
  end;
  LNf := LNa;
  LNg := LNb;
  TX25519Field.Apm(AR.Y, AR.X, LB, LA);
  TX25519Field.Mul(LNa, AP.YmxH, LNa);
  TX25519Field.Mul(LNb, AP.YpxH, LNb);
  TX25519Field.Mul(AR.U, AR.V, LC);
  TX25519Field.Mul(LC, AP.Xyd, LC);
  TX25519Field.Apm(LB, LA, LH, LE);
  TX25519Field.Apm(AR.Z, LC, LNg, LNf);
  TX25519Field.Mul(LF, LG, AR.Z);
  TX25519Field.Mul(LF, LE, AR.X);
  TX25519Field.Mul(LG, LH, AR.Y);
end;

class procedure TEd25519.PointAddVar(ANegate: Boolean; const AP: TPointPrecompZ; var AR: TPointAccum; var AT: TPointTemp);
var
  LNa, LNb, LNf, LNg: TCryptoLibInt32Array;
  LA, LB, LC, LD, LE, LF, LG, LH: TCryptoLibInt32Array;
begin
  LA := AR.X;
  LB := AR.Y;
  LC := AT.R0;
  LD := AT.R1;
  LE := AR.U;
  LF := LA;
  LG := LB;
  LH := AR.V;
  if ANegate then
  begin
    LNa := LB;
    LNb := LA;
  end
  else
  begin
    LNa := LA;
    LNb := LB;
  end;
  LNf := LNa;
  LNg := LNb;
  TX25519Field.Apm(AR.Y, AR.X, LB, LA);
  TX25519Field.Mul(LNa, AP.YmxH, LNa);
  TX25519Field.Mul(LNb, AP.YpxH, LNb);
  TX25519Field.Mul(AR.U, AR.V, LC);
  TX25519Field.Mul(LC, AP.Xyd, LC);
  TX25519Field.Mul(AR.Z, AP.Z, LD);
  TX25519Field.Apm(LB, LA, LH, LE);
  TX25519Field.Apm(LD, LC, LNg, LNf);
  TX25519Field.Mul(LF, LG, AR.Z);
  TX25519Field.Mul(LF, LE, AR.X);
  TX25519Field.Mul(LG, LH, AR.Y);
end;

class procedure TEd25519.PointCopy(const AP: TPointAccum; var AR: TPointExtended);
begin
  TX25519Field.Copy(AP.X, 0, AR.X, 0);
  TX25519Field.Copy(AP.Y, 0, AR.Y, 0);
  TX25519Field.Copy(AP.Z, 0, AR.Z, 0);
  TX25519Field.Mul(AP.U, AP.V, AR.T);
end;

class procedure TEd25519.PointCopy(const AP: TPointAffine; var AR: TPointExtended);
begin
  TX25519Field.Copy(AP.X, 0, AR.X, 0);
  TX25519Field.Copy(AP.Y, 0, AR.Y, 0);
  TX25519Field.One(AR.Z);
  TX25519Field.Mul(AP.X, AP.Y, AR.T);
end;

class procedure TEd25519.PointCopy(const AP: TPointExtended; var AR: TPointPrecompZ);
begin
  TX25519Field.Apm(AP.Y, AP.X, AR.YpxH, AR.YmxH);
  TX25519Field.Mul(AP.T, FC_d2, AR.Xyd);
  TX25519Field.Add(AP.Z, AP.Z, AR.Z);
end;

class procedure TEd25519.PointDouble(var AR: TPointAccum);
var
  LA, LB, LC, LE, LF, LG, LH: TCryptoLibInt32Array;
begin
  LA := AR.X;
  LB := AR.Y;
  LC := AR.Z;
  LE := AR.U;
  LF := LA;
  LG := LB;
  LH := AR.V;
  TX25519Field.Add(AR.X, AR.Y, LE);
  TX25519Field.Sqr(AR.X, LA);
  TX25519Field.Sqr(AR.Y, LB);
  TX25519Field.Sqr(AR.Z, LC);
  TX25519Field.Add(LC, LC, LC);
  TX25519Field.Apm(LA, LB, LH, LG);
  TX25519Field.Sqr(LE, LE);
  TX25519Field.Sub(LH, LE, LE);
  TX25519Field.Add(LC, LG, LF);
  TX25519Field.Carry(LF);
  TX25519Field.Mul(LF, LG, AR.Z);
  TX25519Field.Mul(LF, LE, AR.X);
  TX25519Field.Mul(LG, LH, AR.Y);
end;

class procedure TEd25519.PointLookup(ABlock, AIndex: Int32; var AP: TPointPrecomp);
var
  LOff: Int32;
  LI: Int32;
  LCond: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert((0 <= ABlock) and (ABlock < PrecompBlocks));
  System.Assert((0 <= AIndex) and (AIndex < PrecompPoints));
  {$ENDIF}
  LOff := ABlock * PrecompPoints * 3 * TX25519Field.Size;
  LI := 0;
  while LI < PrecompPoints do
  begin
    LCond := TBitOperations.Asr32((LI xor AIndex) - 1, 31);
    TX25519Field.CMov(LCond, FPrecompBaseComb, LOff, AP.YmxH, 0);
    LOff := LOff + TX25519Field.Size;
    TX25519Field.CMov(LCond, FPrecompBaseComb, LOff, AP.YpxH, 0);
    LOff := LOff + TX25519Field.Size;
    TX25519Field.CMov(LCond, FPrecompBaseComb, LOff, AP.Xyd, 0);
    LOff := LOff + TX25519Field.Size;
    System.Inc(LI);
  end;
end;

class procedure TEd25519.PointLookupZ(const AX: TCryptoLibUInt32Array; AN: Int32; const ATable: TCryptoLibInt32Array; var AR: TPointPrecompZ);
var
  LW: UInt32;
  LSign, LAbs: Int32;
  LI: Int32;
  LOff: Int32;
  LCond: Int32;
begin
  LW := GetWindow4(AX, AN);
  LSign := Int32(LW shr (4 - 1)) xor 1;
  LAbs := (Int32(LW) xor -LSign) and 7;
  {$IFDEF DEBUG}
  System.Assert((LSign = 0) or (LSign = 1));
  System.Assert((0 <= LAbs) and (LAbs < 8));
  {$ENDIF}
  LOff := 0;
  LI := 0;
  while LI < 8 do
  begin
    LCond := TBitOperations.Asr32((LI xor LAbs) - 1, 31);
    TX25519Field.CMov(LCond, ATable, LOff, AR.YmxH, 0);
    LOff := LOff + TX25519Field.Size;
    TX25519Field.CMov(LCond, ATable, LOff, AR.YpxH, 0);
    LOff := LOff + TX25519Field.Size;
    TX25519Field.CMov(LCond, ATable, LOff, AR.Xyd, 0);
    LOff := LOff + TX25519Field.Size;
    TX25519Field.CMov(LCond, ATable, LOff, AR.Z, 0);
    LOff := LOff + TX25519Field.Size;
    System.Inc(LI);
  end;
  TX25519Field.CSwap(LSign, AR.YmxH, AR.YpxH);
  TX25519Field.CNegate(LSign, AR.Xyd);
end;

class procedure TEd25519.PointPrecompute(const AP: TPointAffine; var APoints: TCryptoLibGenericArray<TPointExtended>; APointsOff, APointsLen: Int32; var AT: TPointTemp);
var
  LD: TPointExtended;
  LI: Int32;
begin
  InitPointExtended(APoints[APointsOff]);
  PointCopy(AP, APoints[APointsOff]);
  InitPointExtended(LD);
  PointAdd(APoints[APointsOff], APoints[APointsOff], LD, AT);
  LI := 1;
  while LI < APointsLen do
  begin
    InitPointExtended(APoints[APointsOff + LI]);
    PointAdd(APoints[APointsOff + LI - 1], LD, APoints[APointsOff + LI], AT);
    System.Inc(LI);
  end;
end;

class function TEd25519.PointPrecomputeZ(const AP: TPointAffine; ACount: Int32; var AT: TPointTemp): TCryptoLibInt32Array;
var
  LQ, LD: TPointExtended;
  LR: TPointPrecompZ;
  LOff, LI: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(ACount > 0);
  {$ENDIF}
  InitPointExtended(LQ);
  PointCopy(AP, LQ);
  InitPointExtended(LD);
  PointAdd(LQ, LQ, LD, AT);
  InitPointPrecompZ(LR);
  System.SetLength(Result, ACount * 4 * TX25519Field.Size);
  LOff := 0;
  LI := 0;
  repeat
    PointCopy(LQ, LR);
    TX25519Field.Copy(LR.YmxH, 0, Result, LOff);
    LOff := LOff + TX25519Field.Size;
    TX25519Field.Copy(LR.YpxH, 0, Result, LOff);
    LOff := LOff + TX25519Field.Size;
    TX25519Field.Copy(LR.Xyd, 0, Result, LOff);
    LOff := LOff + TX25519Field.Size;
    TX25519Field.Copy(LR.Z, 0, Result, LOff);
    LOff := LOff + TX25519Field.Size;
    System.Inc(LI);
    if LI = ACount then
      break;
    PointAdd(LQ, LD, LQ, AT);
  until False;
end;

class procedure TEd25519.PointPrecomputeZ(const AP: TPointAffine; var APoints: TCryptoLibGenericArray<TPointPrecompZ>; ACount: Int32; var AT: TPointTemp);
var
  LQ, LD: TPointExtended;
  LI: Int32;
begin
  InitPointExtended(LQ);
  PointCopy(AP, LQ);
  InitPointExtended(LD);
  PointAdd(LQ, LQ, LD, AT);
  LI := 0;
  repeat
    InitPointPrecompZ(APoints[LI]);
    PointCopy(LQ, APoints[LI]);
    System.Inc(LI);
    if LI = ACount then
      break;
    PointAdd(LQ, LD, LQ, AT);
  until False;
end;

class procedure TEd25519.PointSetNeutral(var AP: TPointAccum);
begin
  TX25519Field.Zero(AP.X);
  TX25519Field.One(AP.Y);
  TX25519Field.One(AP.Z);
  TX25519Field.Zero(AP.U);
  TX25519Field.One(AP.V);
end;

class procedure TEd25519.PruneScalar(const AN: TCryptoLibByteArray; ANOff: Int32; AR: TCryptoLibByteArray);
begin
  System.Move(AN[ANOff], AR[0], ScalarBytes);
  AR[0] := AR[0] and $F8;
  AR[ScalarBytes - 1] := AR[ScalarBytes - 1] and $7F;
  AR[ScalarBytes - 1] := AR[ScalarBytes - 1] or $40;
end;

class procedure TEd25519.ScalarMult(const AK: TCryptoLibByteArray; const AP: TPointAffine; var AR: TPointAccum);
var
  LN: TCryptoLibUInt32Array;
  LQ: TPointPrecompZ;
  LT: TPointTemp;
  LTable: TCryptoLibInt32Array;
  LW, LJ: Int32;
begin
  System.SetLength(LN, ScalarUints);
  TScalar25519.Decode(AK, LN);
  TScalar25519.ToSignedDigits(256, LN);
  InitPointPrecompZ(LQ);
  InitPointTemp(LT);
  LTable := PointPrecomputeZ(AP, 8, LT);
  PointSetNeutral(AR);
  LW := 63;
  repeat
    PointLookupZ(LN, LW, LTable, LQ);
    PointAdd(LQ, AR, LT);
    System.Dec(LW);
    if LW < 0 then
      break;
    LJ := 0;
    while LJ < 4 do
    begin
      PointDouble(AR);
      System.Inc(LJ);
    end;
  until False;
end;

class procedure TEd25519.ScalarMultBase(const AK: TCryptoLibByteArray; var AR: TPointAccum);
var
  LN: TCryptoLibUInt32Array;
  LP: TPointPrecomp;
  LT: TPointTemp;
  LCOff: Int32;
  LBlock: Int32;
  LW: UInt32;
  LSign, LAbs, LResultSign: Int32;
begin
  Precompute;
  System.SetLength(LN, ScalarUints);
  TScalar25519.Decode(AK, LN);
  TScalar25519.ToSignedDigits(PrecompRange, LN);
  GroupCombBits(LN);
  InitPointPrecomp(LP);
  InitPointTemp(LT);
  PointSetNeutral(AR);
  LResultSign := 0;
  LCOff := (PrecompSpacing - 1) * PrecompTeeth;
  repeat
    LBlock := 0;
    while LBlock < PrecompBlocks do
    begin
      LW := LN[LBlock] shr LCOff;
      LSign := TBitOperations.Asr32(Int32(LW), PrecompTeeth - 1) and 1;
      LAbs := (Int32(LW) xor -LSign) and PrecompMask;
      {$IFDEF DEBUG}
      System.Assert((LSign = 0) or (LSign = 1));
      System.Assert((0 <= LAbs) and (LAbs < PrecompPoints));
      {$ENDIF}
      PointLookup(LBlock, LAbs, LP);
      TX25519Field.CNegate(LResultSign xor LSign, AR.X);
      TX25519Field.CNegate(LResultSign xor LSign, AR.U);
      LResultSign := LSign;
      PointAdd(LP, AR, LT);
      System.Inc(LBlock);
    end;
    LCOff := LCOff - PrecompTeeth;
    if LCOff < 0 then
      break;
    PointDouble(AR);
  until False;
  TX25519Field.CNegate(LResultSign, AR.X);
  TX25519Field.CNegate(LResultSign, AR.U);
end;

class procedure TEd25519.ScalarMultBaseEncoded(const AK: TCryptoLibByteArray; AR: TCryptoLibByteArray; AROff: Int32);
var
  LP: TPointAccum;
begin
  InitPointAccum(LP);
  ScalarMultBase(AK, LP);
  if EncodeResult(LP, AR, AROff) = 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);
end;

class procedure TEd25519.ScalarMultBaseYZ(const AK: TCryptoLibByteArray; AKOff: Int32; AY, AZ: TCryptoLibInt32Array);
var
  LN: TCryptoLibByteArray;
  LP: TPointAccum;
begin
  System.SetLength(LN, ScalarBytes);
  PruneScalar(AK, AKOff, LN);
  InitPointAccum(LP);
  ScalarMultBase(LN, LP);
  if CheckPoint(LP) = 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);
  TX25519Field.Copy(LP.Y, 0, AY, 0);
  TX25519Field.Copy(LP.Z, 0, AZ, 0);
end;

class procedure TEd25519.ScalarMultOrderVar(const AP: TPointAffine; var AR: TPointAccum);
var
  LWsP: TCryptoLibShortIntArray;
  LCount: Int32;
  LTp: TCryptoLibGenericArray<TPointPrecompZ>;
  LT: TPointTemp;
  LBit, LWP, LIndex: Int32;
begin
  System.SetLength(LWsP, 253);
  TScalar25519.GetOrderWnafVar(WnafWidth128, LWsP);
  LCount := 1 shl (WnafWidth128 - 2);
  System.SetLength(LTp, LCount);
  InitPointTemp(LT);
  PointPrecomputeZ(AP, LTp, LCount, LT);
  PointSetNeutral(AR);
  LBit := 252;
  repeat
    LWP := LWsP[LBit];
    if LWP <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWP, 1) xor TBitOperations.Asr32(LWP, 31);
      PointAddVar(LWP < 0, LTp[LIndex], AR, LT);
    end;
    System.Dec(LBit);
    if LBit < 0 then
      break;
    PointDouble(AR);
  until False;
end;

class function TEd25519.CheckPointOrderVar(var AP: TPointAffine): Boolean;
var
  LR: TPointAccum;
begin
  InitPointAccum(LR);
  ScalarMultOrderVar(AP, LR);
  Result := NormalizeToNeutralElementVar(LR);
end;

class function TEd25519.ExportPoint(var AP: TPointAffine): IPublicPoint;
var
  LData: TCryptoLibInt32Array;
begin
  System.SetLength(LData, TX25519Field.Size * 2);
  TX25519Field.Copy(AP.X, 0, LData, 0);
  TX25519Field.Copy(AP.Y, 0, LData, TX25519Field.Size);
  Result := TPublicPoint.Create(LData);
end;

class procedure TEd25519.EncodePublicPoint(const APublicPoint: IPublicPoint; APk: TCryptoLibByteArray; APkOff: Int32);
var
  LData: TCryptoLibInt32Array;
begin
  LData := APublicPoint.Data;
  TX25519Field.Encode(LData, TX25519Field.Size, APk, APkOff);
  APk[APkOff + PointBytes - 1] := APk[APkOff + PointBytes - 1] or Byte((LData[0] and 1) shl 7);
end;

class function TEd25519.GeneratePublicKey(const &AS: TCryptoLibByteArray; ASOff: Int32): IPublicPoint;
var
  LD: IDigest;
  LH, LS: TCryptoLibByteArray;
  LP: TPointAccum;
  LQ: TPointAffine;
begin
  LD := CreateDigest();
  System.SetLength(LH, 64);
  LD.BlockUpdate(&AS, ASOff, SecretKeySize);
  LD.DoFinal(LH, 0);
  System.SetLength(LS, ScalarBytes);
  PruneScalar(LH, 0, LS);
  InitPointAccum(LP);
  ScalarMultBase(LS, LP);
  InitPointAffine(LQ);
  NormalizeToAffine(LP, LQ);
  if CheckPoint(LQ) = 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);
  Result := ExportPoint(LQ);
end;

class function TEd25519.ValidatePublicKeyFull(const APk: TCryptoLibByteArray; APkOff: Int32): Boolean;
var
  LA: TCryptoLibByteArray;
  LPA: TPointAffine;
begin
  System.SetLength(LA, PublicKeySize);
  System.Move(APk[APkOff], LA[0], PublicKeySize);
  if not CheckPointFullVar(LA) then
    Exit(False);
  InitPointAffine(LPA);
  if not DecodePointVar(LA, False, LPA) then
    Exit(False);
  Result := CheckPointOrderVar(LPA);
end;

class function TEd25519.ValidatePublicKeyFullExport(const APk: TCryptoLibByteArray; APkOff: Int32): IPublicPoint;
var
  LA: TCryptoLibByteArray;
  LPA: TPointAffine;
begin
  Result := nil;
  System.SetLength(LA, PublicKeySize);
  System.Move(APk[APkOff], LA[0], PublicKeySize);
  if not CheckPointFullVar(LA) then
    Exit;
  InitPointAffine(LPA);
  if not DecodePointVar(LA, False, LPA) then
    Exit;
  if not CheckPointOrderVar(LPA) then
    Exit;
  Result := ExportPoint(LPA);
end;

class function TEd25519.ValidatePublicKeyPartial(const APk: TCryptoLibByteArray; APkOff: Int32): Boolean;
var
  LA: TCryptoLibByteArray;
  LPA: TPointAffine;
begin
  System.SetLength(LA, PublicKeySize);
  System.Move(APk[APkOff], LA[0], PublicKeySize);
  if not CheckPointFullVar(LA) then
    Exit(False);
  InitPointAffine(LPA);
  Result := DecodePointVar(LA, False, LPA);
end;

class function TEd25519.ValidatePublicKeyPartialExport(const APk: TCryptoLibByteArray; APkOff: Int32): IPublicPoint;
var
  LA: TCryptoLibByteArray;
  LPA: TPointAffine;
begin
  Result := nil;
  System.SetLength(LA, PublicKeySize);
  System.Move(APk[APkOff], LA[0], PublicKeySize);
  if not CheckPointFullVar(LA) then
    Exit;
  InitPointAffine(LPA);
  if not DecodePointVar(LA, False, LPA) then
    Exit;
  Result := ExportPoint(LPA);
end;

class procedure TEd25519.ScalarMultStraus128Var(const ANb: TCryptoLibUInt32Array; const ANp: TCryptoLibUInt32Array; const AP: TPointAffine;
  const ANq: TCryptoLibUInt32Array; const AQ: TPointAffine; var AR: TPointAccum);
var
  LWsB: TCryptoLibShortIntArray;
  LWsP, LWsQ: TCryptoLibShortIntArray;
  LCount: Int32;
  LTp, LTq: TCryptoLibGenericArray<TPointPrecompZ>;
  LT: TPointTemp;
  LBit, LWB, LWB128, LWP, LWQ, LIndex: Int32;
begin
  {$IFDEF DEBUG}
  System.Assert(System.Length(ANb) = ScalarUints);
  System.Assert((ANb[ScalarUints - 1] shr 29) = 0);
  System.Assert(System.Length(ANp) = 4);
  System.Assert(System.Length(ANq) = 4);
  {$ENDIF}
  Precompute();
  System.SetLength(LWsB, 256);
  System.SetLength(LWsP, 128);
  System.SetLength(LWsQ, 128);
  TWnaf.GetSignedVar(ANb, WnafWidthBase, LWsB);
  TWnaf.GetSignedVar(ANp, WnafWidth128, LWsP);
  TWnaf.GetSignedVar(ANq, WnafWidth128, LWsQ);
  LCount := 1 shl (WnafWidth128 - 2);
  System.SetLength(LTp, LCount);
  System.SetLength(LTq, LCount);
  InitPointTemp(LT);
  PointPrecomputeZ(AP, LTp, LCount, LT);
  PointPrecomputeZ(AQ, LTq, LCount, LT);
  PointSetNeutral(AR);
  LBit := 128;
  while LBit > 0 do
  begin
    System.Dec(LBit);
    if (Int32(LWsB[LBit]) or Int32(LWsB[128 + LBit]) or Int32(LWsP[LBit]) or Int32(LWsQ[LBit])) <> 0 then
      break;
  end;
  while LBit >= 0 do
  begin
    LWB := LWsB[LBit];
    if LWB <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWB, 1) xor TBitOperations.Asr32(LWB, 31);
      PointAddVar(LWB < 0, FPrecompBaseWnaf[LIndex], AR, LT);
    end;
    LWB128 := LWsB[128 + LBit];
    if LWB128 <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWB128, 1) xor TBitOperations.Asr32(LWB128, 31);
      PointAddVar(LWB128 < 0, FPrecompBase128Wnaf[LIndex], AR, LT);
    end;
    LWP := LWsP[LBit];
    if LWP <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWP, 1) xor TBitOperations.Asr32(LWP, 31);
      PointAddVar(LWP < 0, LTp[LIndex], AR, LT);
    end;
    LWQ := LWsQ[LBit];
    if LWQ <> 0 then
    begin
      LIndex := TBitOperations.Asr32(LWQ, 1) xor TBitOperations.Asr32(LWQ, 31);
      PointAddVar(LWQ < 0, LTq[LIndex], AR, LT);
    end;
    PointDouble(AR);
    System.Dec(LBit);
  end;
  PointDouble(AR);
  PointDouble(AR);
end;

class procedure TEd25519.Precompute;
var
  LWnafPoints, LCombPoints, LTotalPoints: Int32;
  LPoints: TCryptoLibGenericArray<TPointExtended>;
  LT: TPointTemp;
  LB, LB128: TPointAffine;
  LP: TPointAccum;
  LPointsIndex: Int32;
  LToothPowers: TCryptoLibGenericArray<TPointExtended>;
  LTooth, LBlock, LSpacing, LSize, LJ: Int32;
  LU: TPointExtended;
  LPointsIndex2: Int32;
  LS: TPointPrecomp;
  LOff: Int32;
  LI: Int32;
begin
  FPrecompLock.Enter;
  try
    if FPrecompBaseComb <> nil then
      Exit;
    LWnafPoints := 1 shl (WnafWidthBase - 2);
    LCombPoints := PrecompBlocks * PrecompPoints;
    LTotalPoints := LWnafPoints * 2 + LCombPoints;
    System.SetLength(LPoints, LTotalPoints);
    InitPointTemp(LT);
    InitPointAffine(LB);
    TX25519Field.Copy(FB_x, 0, LB.X, 0);
    TX25519Field.Copy(FB_y, 0, LB.Y, 0);
    PointPrecompute(LB, LPoints, 0, LWnafPoints, LT);
    InitPointAffine(LB128);
    TX25519Field.Copy(FB128_x, 0, LB128.X, 0);
    TX25519Field.Copy(FB128_y, 0, LB128.Y, 0);
    PointPrecompute(LB128, LPoints, LWnafPoints, LWnafPoints, LT);
    InitPointAccum(LP);
    TX25519Field.Copy(FB_x, 0, LP.X, 0);
    TX25519Field.Copy(FB_y, 0, LP.Y, 0);
    TX25519Field.One(LP.Z);
    TX25519Field.Copy(FB_x, 0, LP.U, 0);
    TX25519Field.Copy(FB_y, 0, LP.V, 0);
    LPointsIndex := LWnafPoints * 2;
    System.SetLength(LToothPowers, PrecompTeeth);
    for LTooth := 0 to PrecompTeeth - 1 do
      InitPointExtended(LToothPowers[LTooth]);
    InitPointExtended(LU);
    for LBlock := 0 to PrecompBlocks - 1 do
    begin
      InitPointExtended(LPoints[LPointsIndex]);
      for LTooth := 0 to PrecompTeeth - 1 do
      begin
        if LTooth = 0 then
          PointCopy(LP, LPoints[LPointsIndex])
        else
        begin
          PointCopy(LP, LU);
          PointAdd(LPoints[LPointsIndex], LU, LPoints[LPointsIndex], LT);
        end;
        PointDouble(LP);
        PointCopy(LP, LToothPowers[LTooth]);
        if LBlock + LTooth <> PrecompBlocks + PrecompTeeth - 2 then
        begin
          for LSpacing := 1 to PrecompSpacing - 1 do
            PointDouble(LP);
        end;
      end;
      TX25519Field.Negate(LPoints[LPointsIndex].X, LPoints[LPointsIndex].X);
      TX25519Field.Negate(LPoints[LPointsIndex].T, LPoints[LPointsIndex].T);
      System.Inc(LPointsIndex);
      for LTooth := 0 to PrecompTeeth - 2 do
      begin
        LSize := 1 shl LTooth;
        for LJ := 0 to LSize - 1 do
        begin
          InitPointExtended(LPoints[LPointsIndex]);
          PointAdd(LPoints[LPointsIndex - LSize], LToothPowers[LTooth], LPoints[LPointsIndex], LT);
          System.Inc(LPointsIndex);
        end;
      end;
    end;
    {$IFDEF DEBUG}
    System.Assert(LPointsIndex = LTotalPoints);
    {$ENDIF}
    InvertDoubleZs(LPoints);
    System.SetLength(FPrecompBaseWnaf, LWnafPoints);
    for LI := 0 to LWnafPoints - 1 do
    begin
      InitPointPrecomp(FPrecompBaseWnaf[LI]);
      TX25519Field.Mul(LPoints[LI].X, LPoints[LI].Z, LPoints[LI].X);
      TX25519Field.Mul(LPoints[LI].Y, LPoints[LI].Z, LPoints[LI].Y);
      TX25519Field.Apm(LPoints[LI].Y, LPoints[LI].X, FPrecompBaseWnaf[LI].YpxH, FPrecompBaseWnaf[LI].YmxH);
      TX25519Field.Mul(LPoints[LI].X, LPoints[LI].Y, FPrecompBaseWnaf[LI].Xyd);
      TX25519Field.Mul(FPrecompBaseWnaf[LI].Xyd, FC_d4, FPrecompBaseWnaf[LI].Xyd);
      TX25519Field.Normalize(FPrecompBaseWnaf[LI].YmxH);
      TX25519Field.Normalize(FPrecompBaseWnaf[LI].YpxH);
      TX25519Field.Normalize(FPrecompBaseWnaf[LI].Xyd);
    end;
    System.SetLength(FPrecompBase128Wnaf, LWnafPoints);
    for LI := 0 to LWnafPoints - 1 do
    begin
      InitPointPrecomp(FPrecompBase128Wnaf[LI]);
      LPointsIndex2 := LWnafPoints + LI;
      TX25519Field.Mul(LPoints[LPointsIndex2].X, LPoints[LPointsIndex2].Z, LPoints[LPointsIndex2].X);
      TX25519Field.Mul(LPoints[LPointsIndex2].Y, LPoints[LPointsIndex2].Z, LPoints[LPointsIndex2].Y);
      TX25519Field.Apm(LPoints[LPointsIndex2].Y, LPoints[LPointsIndex2].X, FPrecompBase128Wnaf[LI].YpxH, FPrecompBase128Wnaf[LI].YmxH);
      TX25519Field.Mul(LPoints[LPointsIndex2].X, LPoints[LPointsIndex2].Y, FPrecompBase128Wnaf[LI].Xyd);
      TX25519Field.Mul(FPrecompBase128Wnaf[LI].Xyd, FC_d4, FPrecompBase128Wnaf[LI].Xyd);
      TX25519Field.Normalize(FPrecompBase128Wnaf[LI].YmxH);
      TX25519Field.Normalize(FPrecompBase128Wnaf[LI].YpxH);
      TX25519Field.Normalize(FPrecompBase128Wnaf[LI].Xyd);
    end;
    FPrecompBaseComb := TX25519Field.CreateTable(LCombPoints * 3);
    InitPointPrecomp(LS);
    LOff := 0;
    for LI := LWnafPoints * 2 to LTotalPoints - 1 do
    begin
      TX25519Field.Mul(LPoints[LI].X, LPoints[LI].Z, LPoints[LI].X);
      TX25519Field.Mul(LPoints[LI].Y, LPoints[LI].Z, LPoints[LI].Y);
      TX25519Field.Apm(LPoints[LI].Y, LPoints[LI].X, LS.YpxH, LS.YmxH);
      TX25519Field.Mul(LPoints[LI].X, LPoints[LI].Y, LS.Xyd);
      TX25519Field.Mul(LS.Xyd, FC_d4, LS.Xyd);
      TX25519Field.Normalize(LS.YmxH);
      TX25519Field.Normalize(LS.YpxH);
      TX25519Field.Normalize(LS.Xyd);
      TX25519Field.Copy(LS.YmxH, 0, FPrecompBaseComb, LOff);
      LOff := LOff + TX25519Field.Size;
      TX25519Field.Copy(LS.YpxH, 0, FPrecompBaseComb, LOff);
      LOff := LOff + TX25519Field.Size;
      TX25519Field.Copy(LS.Xyd, 0, FPrecompBaseComb, LOff);
      LOff := LOff + TX25519Field.Size;
    end;
    {$IFDEF DEBUG}
    System.Assert(LOff = System.Length(FPrecompBaseComb));
    {$ENDIF}
  finally
    FPrecompLock.Leave;
  end;
end;

function TEd25519.GetAlgorithmName: String;
begin
  Result := 'Ed25519';
end;

class function TEd25519.CreatePreHash(): IDigest;
begin
  Result := CreateDigest();
end;

procedure TEd25519.GeneratePrivateKey(const ARandom: ISecureRandom; const AK: TCryptoLibByteArray);
begin
  ARandom.NextBytes(AK);
end;

procedure TEd25519.GeneratePublicKey(const &AS: TCryptoLibByteArray; ASOff: Int32; APk: TCryptoLibByteArray; APkOff: Int32);
var
  LD: IDigest;
  LH: TCryptoLibByteArray;
  LS: TCryptoLibByteArray;
begin
  LD := CreateDigest();
  System.SetLength(LH, 64);
  LD.BlockUpdate(&AS, ASOff, SecretKeySize);
  LD.DoFinal(LH, 0);
  System.SetLength(LS, ScalarBytes);
  PruneScalar(LH, 0, LS);
  ScalarMultBaseEncoded(LS, APk, APkOff);
end;

procedure TEd25519.Sign(const &AS: TCryptoLibByteArray; ASOff: Int32; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LNullCtx: TCryptoLibByteArray;
begin
  LNullCtx := nil;
  ImplSign(&AS, ASOff, LNullCtx, Byte($00), AM, AMOff, AMLen, ASig, ASigOff);
end;

procedure TEd25519.Sign(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const AM: TCryptoLibByteArray; AMOff, AMLen: Int32; const ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LNullCtx: TCryptoLibByteArray;
begin
  LNullCtx := nil;
  ImplSign(&AS, ASOff, APk, APkOff, LNullCtx, Byte($00), AM, AMOff, AMLen, ASig, ASigOff);
end;

procedure TEd25519.Sign(const &AS: TCryptoLibByteArray; ASOff: Int32; const ACtx, AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32);
begin
  if not CheckContextVar(ACtx, $00) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  ImplSign(&AS, ASOff, ACtx, $00, AM, AMOff, AMLen, ASig, ASigOff);
end;

procedure TEd25519.Sign(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx, AM: TCryptoLibByteArray; AMOff, AMLen: Int32; const ASig: TCryptoLibByteArray; ASigOff: Int32);
begin
  if not CheckContextVar(ACtx, $00) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  ImplSign(&AS, ASOff, APk, APkOff, ACtx, $00, AM, AMOff, AMLen, ASig, ASigOff);
end;

procedure TEd25519.SignPreHash(const &AS: TCryptoLibByteArray; ASOff: Int32; const ACtx, APh: TCryptoLibByteArray; APhOff: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32);
begin
  if not CheckContextVar(ACtx, $01) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  ImplSign(&AS, ASOff, ACtx, $01, APh, APhOff, PrehashSize, ASig, ASigOff);
end;

procedure TEd25519.SignPreHash(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx, APh: TCryptoLibByteArray; APhOff: Int32; const ASig: TCryptoLibByteArray; ASigOff: Int32);
begin
  if not CheckContextVar(ACtx, $01) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  ImplSign(&AS, ASOff, APk, APkOff, ACtx, $01, APh, APhOff, PrehashSize, ASig, ASigOff);
end;

procedure TEd25519.SignPreHash(const &AS: TCryptoLibByteArray; ASOff: Int32; const ACtx: TCryptoLibByteArray; const APh: IDigest;
  const ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LM: TCryptoLibByteArray;
begin
  System.SetLength(LM, PrehashSize);
  if APh.DoFinal(LM, 0) <> PrehashSize then
    raise EArgumentCryptoLibException.CreateRes(@SDigestSize);
  SignPreHash(&AS, ASOff, ACtx, LM, 0, ASig, ASigOff);
end;

procedure TEd25519.SignPreHash(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx: TCryptoLibByteArray; const APh: IDigest; const ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LM: TCryptoLibByteArray;
begin
  System.SetLength(LM, PrehashSize);
  if APh.DoFinal(LM, 0) <> PrehashSize then
    raise EArgumentCryptoLibException.CreateRes(@SDigestSize);
  SignPreHash(&AS, ASOff, APk, APkOff, ACtx, LM, 0, ASig, ASigOff);
end;

class procedure TEd25519.ImplSign(const AD: IDigest; AH, &AS, APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32;
  ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LR, LK, LS: TCryptoLibByteArray;
  LRBytes: TCryptoLibByteArray;
begin
  if (ACtx <> nil) or (APhflag = $01) then
    Dom2(AD, APhflag, ACtx);
  AD.BlockUpdate(AH, ScalarBytes, ScalarBytes);
  AD.BlockUpdate(AM, AMOff, AMLen);
  AD.DoFinal(AH, 0);
  LR := TScalar25519.Reduce512(AH);
  System.SetLength(LRBytes, PointBytes);
  ScalarMultBaseEncoded(LR, LRBytes, 0);
  if (ACtx <> nil) or (APhflag = $01) then
    Dom2(AD, APhflag, ACtx);
  AD.BlockUpdate(LRBytes, 0, PointBytes);
  AD.BlockUpdate(APk, APkOff, PointBytes);
  AD.BlockUpdate(AM, AMOff, AMLen);
  AD.DoFinal(AH, 0);
  LK := TScalar25519.Reduce512(AH);
  LS := CalculateS(LR, LK, &AS);
  System.Move(LRBytes[0], ASig[ASigOff], PointBytes);
  System.Move(LS[0], ASig[ASigOff + PointBytes], ScalarBytes);
end;

function TEd25519.Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
begin
  Result := ImplVerify(ASig, ASigOff, APk, APkOff, nil, $00, AM, AMOff, AMLen);
end;

function TEd25519.Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx, AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
begin
  if not CheckContextVar(ACtx, $00) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  Result := ImplVerify(ASig, ASigOff, APk, APkOff, ACtx, $00, AM, AMOff, AMLen);
end;

function TEd25519.Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
  const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
begin
  Result := ImplVerify(ASig, ASigOff, APublicPoint, nil, $00, AM, AMOff, AMLen);
end;

function TEd25519.Verify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
  const ACtx, AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
begin
  if not CheckContextVar(ACtx, $00) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  Result := ImplVerify(ASig, ASigOff, APublicPoint, ACtx, $00, AM, AMOff, AMLen);
end;

function TEd25519.VerifyPreHash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx, APh: TCryptoLibByteArray; APhOff: Int32): Boolean;
begin
  if not CheckContextVar(ACtx, $01) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  Result := ImplVerify(ASig, ASigOff, APk, APkOff, ACtx, $01, APh, APhOff, PrehashSize);
end;

function TEd25519.VerifyPreHash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx: TCryptoLibByteArray; const APh: IDigest): Boolean;
var
  LM: TCryptoLibByteArray;
begin
  System.SetLength(LM, PrehashSize);
  if APh.DoFinal(LM, 0) <> PrehashSize then
    raise EArgumentCryptoLibException.CreateRes(@SDigestSize);
  Result := VerifyPreHash(ASig, ASigOff, APk, APkOff, ACtx, LM, 0);
end;

function TEd25519.VerifyPreHash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
  const ACtx, APh: TCryptoLibByteArray; APhOff: Int32): Boolean;
begin
  if not CheckContextVar(ACtx, $01) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  Result := ImplVerify(ASig, ASigOff, APublicPoint, ACtx, $01, APh, APhOff, PrehashSize);
end;

function TEd25519.VerifyPreHash(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
  const ACtx: TCryptoLibByteArray; const APh: IDigest): Boolean;
var
  LM: TCryptoLibByteArray;
begin
  System.SetLength(LM, PrehashSize);
  if APh.DoFinal(LM, 0) <> PrehashSize then
    raise EArgumentCryptoLibException.CreateRes(@SDigestSize);
  Result := VerifyPreHash(ASig, ASigOff, APublicPoint, ACtx, LM, 0);
end;

class function TEd25519.ImplVerify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APublicPoint: IPublicPoint;
  const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
var
  LR, LS, LA: TCryptoLibByteArray;
  LNS: TCryptoLibUInt32Array;
  LNA: TCryptoLibUInt32Array;
  LV0, LV1: TCryptoLibUInt32Array;
  LPR, LPA: TPointAffine;
  LPZ: TPointAccum;
  LD: IDigest;
  LH: TCryptoLibByteArray;
  LK: TCryptoLibByteArray;
  LData: TCryptoLibInt32Array;
begin
  if not CheckContextVar(ACtx, APhflag) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidCtx);
  CopyBytes(ASig, ASigOff, PointBytes, LR);
  CopyBytes(ASig, ASigOff + PointBytes, ScalarBytes, LS);
  System.SetLength(LA, PublicKeySize);
  EncodePublicPoint(APublicPoint, LA, 0);
  if not CheckPointVar(LR) then
  begin
    Exit(False);
  end;
  System.SetLength(LNS, ScalarUints);
  if not TScalar25519.CheckVar(LS, LNS) then
  begin
    Exit(False);
  end;
  InitPointAffine(LPR);
  if not DecodePointVar(LR, True, LPR) then
  begin
    Exit(False);
  end;
  InitPointAffine(LPA);
  LData := APublicPoint.Data;
  TX25519Field.Negate(LData, LPA.X);
  TX25519Field.Copy(LData, TX25519Field.Size, LPA.Y, 0);
  LD := CreateDigest();
  System.SetLength(LH, 64);
  if (ACtx <> nil) or (APhflag = $01) then
    Dom2(LD, APhflag, ACtx);
  LD.BlockUpdate(LR, 0, PointBytes);
  LD.BlockUpdate(LA, 0, PointBytes);
  LD.BlockUpdate(AM, AMOff, AMLen);
  LD.DoFinal(LH, 0);
  LK := TScalar25519.Reduce512(LH);
  System.SetLength(LNA, ScalarUints);
  TScalar25519.Decode(LK, LNA);
  System.SetLength(LV0, 4);
  System.SetLength(LV1, 4);
  if not TScalar25519.ReduceBasisVar(LNA, LV0, LV1) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);
  TScalar25519.Multiply128Var(LNS, LV1, LNS);
  InitPointAccum(LPZ);
  ScalarMultStraus128Var(LNS, LV0, LPA, LV1, LPR, LPZ);
  Result := NormalizeToNeutralElementVar(LPZ);
end;

class function TEd25519.ImplVerify(const ASig: TCryptoLibByteArray; ASigOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff, AMLen: Int32): Boolean;
var
  LR, LS, LA: TCryptoLibByteArray;
  LNS: TCryptoLibUInt32Array;
  LNA: TCryptoLibUInt32Array;
  LV0, LV1: TCryptoLibUInt32Array;
  LPR, LPA: TPointAffine;
  LPZ: TPointAccum;
  LD: IDigest;
  LH: TCryptoLibByteArray;
  LK: TCryptoLibByteArray;
begin
  CopyBytes(ASig, ASigOff, PointBytes, LR);
  CopyBytes(ASig, ASigOff + PointBytes, ScalarBytes, LS);
  CopyBytes(APk, APkOff, PublicKeySize, LA);
  if not CheckPointVar(LR) then
  begin
    Exit(False);
  end;
  System.SetLength(LNS, ScalarUints);
  if not TScalar25519.CheckVar(LS, LNS) then
  begin
    Exit(False);
  end;
  if not CheckPointFullVar(LA) then
  begin
    Exit(False);
  end;
  InitPointAffine(LPR);
  if not DecodePointVar(LR, True, LPR) then
  begin
    Exit(False);
  end;
  InitPointAffine(LPA);
  if not DecodePointVar(LA, True, LPA) then
  begin
    Exit(False);
  end;
  LD := CreateDigest();
  System.SetLength(LH, 64);
  if (ACtx <> nil) or (APhflag = $01) then
    Dom2(LD, APhflag, ACtx);
  LD.BlockUpdate(LR, 0, PointBytes);
  LD.BlockUpdate(LA, 0, PointBytes);
  LD.BlockUpdate(AM, AMOff, AMLen);
  LD.DoFinal(LH, 0);
  LK := TScalar25519.Reduce512(LH);
  System.SetLength(LNA, ScalarUints);
  TScalar25519.Decode(LK, LNA);
  System.SetLength(LV0, 4);
  System.SetLength(LV1, 4);
  if not TScalar25519.ReduceBasisVar(LNA, LV0, LV1) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOp);
  TScalar25519.Multiply128Var(LNS, LV1, LNS);
  InitPointAccum(LPZ);
  ScalarMultStraus128Var(LNS, LV0, LPA, LV1, LPR, LPZ);
  Result := NormalizeToNeutralElementVar(LPZ);
end;

class procedure TEd25519.ImplSign(const &AS: TCryptoLibByteArray; ASOff: Int32; const ACtx: TCryptoLibByteArray; APhflag: Byte;
  const AM: TCryptoLibByteArray; AMOff: Int32; AMLen: Int32; const ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LD: IDigest;
  LH, LS, LPk: TCryptoLibByteArray;
begin
  LD := CreateDigest();
  System.SetLength(LH, 64);
  LD.BlockUpdate(&AS, ASOff, SecretKeySize);
  LD.DoFinal(LH, 0);
  System.SetLength(LS, ScalarBytes);
  PruneScalar(LH, 0, LS);
  System.SetLength(LPk, PointBytes);
  ScalarMultBaseEncoded(LS, LPk, 0);
  ImplSign(LD, LH, LS, LPk, 0, ACtx, APhflag, AM, AMOff, AMLen, ASig, ASigOff);
end;

class procedure TEd25519.ImplSign(const &AS: TCryptoLibByteArray; ASOff: Int32; const APk: TCryptoLibByteArray; APkOff: Int32;
  const ACtx: TCryptoLibByteArray; APhflag: Byte; const AM: TCryptoLibByteArray; AMOff: Int32; AMLen: Int32;
  const ASig: TCryptoLibByteArray; ASigOff: Int32);
var
  LD: IDigest;
  LH, LS: TCryptoLibByteArray;
begin
  LD := CreateDigest();
  System.SetLength(LH, 64);
  LD.BlockUpdate(&AS, ASOff, SecretKeySize);
  LD.DoFinal(LH, 0);
  System.SetLength(LS, ScalarBytes);
  PruneScalar(LH, 0, LS);
  ImplSign(LD, LH, LS, APk, APkOff, ACtx, APhflag, AM, AMOff, AMLen, ASig, ASigOff);
end;

end.
