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

unit GcmReorderTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Math,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBitOperations,
  ClpIGcmMultiplier,
  ClpIGcmExponentiator,
  ClpTables4kGcmMultiplier,
  ClpTables1kGcmExponentiator,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpPack,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestGcmReorder = class(TCryptoLibAlgorithmTestCase)
  strict private
    class var
      FH: TCryptoLibByteArray;
      FRandom: ISecureRandom;
      FMul: IGcmMultiplier;
      FExp: IGcmExponentiator;
      FEmpty: TCryptoLibByteArray;

    class constructor CreateTestGcmReorder;

  private
    function RandomBlocks(AUpper: Int32): TBytes;
    function RandomBytes(AUpper: Int32): TBytes;
    function CombineGhash(const AGhashA: TBytes; ABitlenA: Int64;
      const AGhashC: TBytes; ABitlenC: Int64): TBytes;
    function ConcatAuthGhash(const AGhashP: TBytes; ABitlenP: Int64;
      const AGhashA: TBytes; ABitlenA: Int64): TBytes;
    function ConcatCryptGhash(const AGhashP: TBytes; ABitlenP: Int64;
      const AGhashA: TBytes; ABitlenA: Int64): TBytes;
    function Ghash(const AA, AC: TBytes): TBytes;
    class function LengthBlock(ABitlenA, ABitlenC: Int64): TBytes; static;
    class procedure XorBlock(const ABlock, AVal: TBytes); static;
    class function Multiply(const AA, AB: TBytes): TBytes; static;
    class procedure ShiftRight(const ABlock: TBytes); static;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestCombine;
    procedure TestConcatAuth;
    procedure TestConcatCrypt;
    procedure TestExp;
    procedure TestMultiply;

  end;

implementation

{ TTestGcmReorder }

class constructor TTestGcmReorder.CreateTestGcmReorder;
begin
  FRandom := TSecureRandom.Create();
  System.SetLength(FH, 16);
  FRandom.NextBytes(FH);

  FMul := TTables4kGcmMultiplier.Create();
  FMul.Init(System.Copy(FH));

  FExp := TTables1kGcmExponentiator.Create();
  FExp.Init(System.Copy(FH));

  FEmpty := nil;
end;

procedure TTestGcmReorder.SetUp;
begin
  inherited;
end;

procedure TTestGcmReorder.TearDown;
begin
  inherited;
end;

function TTestGcmReorder.RandomBlocks(AUpper: Int32): TBytes;
begin
  System.SetLength(Result, 16 * FRandom.Next(AUpper));
  FRandom.NextBytes(Result);
end;

function TTestGcmReorder.RandomBytes(AUpper: Int32): TBytes;
begin
  System.SetLength(Result, FRandom.Next(AUpper));
  FRandom.NextBytes(Result);
end;

function TTestGcmReorder.CombineGhash(const AGhashA: TBytes;
  ABitlenA: Int64; const AGhashC: TBytes; ABitlenC: Int64): TBytes;
var
  LC: Int64;
  LHc, LTmp1: TBytes;
begin
  //LHc := nil;
  LC := TBitOperations.Asr64(ABitlenC + 127, 7);

  System.SetLength(LHc, 16);
  FExp.ExponentiateX(LC, LHc);

  LTmp1 := LengthBlock(ABitlenA, 0);
  FMul.MultiplyH(LTmp1);

  Result := System.Copy(AGhashA);
  XorBlock(Result, LTmp1);
  Result := Multiply(Result, LHc);
  XorBlock(Result, LTmp1);
  XorBlock(Result, AGhashC);
end;

function TTestGcmReorder.ConcatAuthGhash(const AGhashP: TBytes;
  ABitlenP: Int64; const AGhashA: TBytes; ABitlenA: Int64): TBytes;
var
  LA: Int64;
  LTmp1, LTmp2, LHa: TBytes;
begin
  LA := TBitOperations.Asr64(ABitlenA + 127, 7);

  LTmp1 := LengthBlock(ABitlenP, 0);
  FMul.MultiplyH(LTmp1);

  LTmp2 := LengthBlock(ABitlenA xor (ABitlenP + ABitlenA), 0);
  FMul.MultiplyH(LTmp2);

  System.SetLength(LHa, 16);
  FExp.ExponentiateX(LA, LHa);

  Result := System.Copy(AGhashP);
  XorBlock(Result, LTmp1);
  Result := Multiply(Result, LHa);
  XorBlock(Result, LTmp2);
  XorBlock(Result, AGhashA);
end;

function TTestGcmReorder.ConcatCryptGhash(const AGhashP: TBytes;
  ABitlenP: Int64; const AGhashA: TBytes; ABitlenA: Int64): TBytes;
var
  LA: Int64;
  LTmp1, LTmp2, LHa: TBytes;
begin
  LA := TBitOperations.Asr64(ABitlenA + 127, 7);

  LTmp1 := LengthBlock(0, ABitlenP);
  FMul.MultiplyH(LTmp1);

  LTmp2 := LengthBlock(0, ABitlenA xor (ABitlenP + ABitlenA));
  FMul.MultiplyH(LTmp2);

  //LHa := nil;
  System.SetLength(LHa, 16);
  FExp.ExponentiateX(LA, LHa);

  Result := System.Copy(AGhashP);
  XorBlock(Result, LTmp1);
  Result := Multiply(Result, LHa);
  XorBlock(Result, LTmp2);
  XorBlock(Result, AGhashA);
end;

function TTestGcmReorder.Ghash(const AA, AC: TBytes): TBytes;
var
  LX, LTmp: TBytes;
  LPos, LNum: Int32;
begin
  //LX := nil;
  System.SetLength(LX, 16);

  LPos := 0;
  while LPos < System.Length(AA) do
  begin
    LTmp := nil;
    System.SetLength(LTmp, 16);
    LNum := Math.Min(System.Length(AA) - LPos, 16);
    System.Move(AA[LPos], LTmp[0], LNum);
    XorBlock(LX, LTmp);
    FMul.MultiplyH(LX);
    Inc(LPos, 16);
  end;

  LPos := 0;
  while LPos < System.Length(AC) do
  begin
    LTmp := nil;
    System.SetLength(LTmp, 16);
    LNum := Math.Min(System.Length(AC) - LPos, 16);
    System.Move(AC[LPos], LTmp[0], LNum);
    XorBlock(LX, LTmp);
    FMul.MultiplyH(LX);
    Inc(LPos, 16);
  end;

  XorBlock(LX, LengthBlock(Int64(System.Length(AA)) * 8,
    Int64(System.Length(AC)) * 8));
  FMul.MultiplyH(LX);

  Result := LX;
end;

class function TTestGcmReorder.LengthBlock(ABitlenA, ABitlenC: Int64): TBytes;
begin
  System.SetLength(Result, 16);
  TPack.UInt64_To_BE(UInt64(ABitlenA), Result, 0);
  TPack.UInt64_To_BE(UInt64(ABitlenC), Result, 8);
end;

class procedure TTestGcmReorder.XorBlock(const ABlock, AVal: TBytes);
var
  LI: Int32;
begin
  for LI := 15 downto 0 do
  begin
    ABlock[LI] := ABlock[LI] xor AVal[LI];
  end;
end;

class function TTestGcmReorder.Multiply(const AA, AB: TBytes): TBytes;
var
  LTmp: TBytes;
  LI, LJ: Int32;
  LBits: Byte;
  LLsb: Boolean;
begin
  Result := nil;
  System.SetLength(Result, 16);
  LTmp := System.Copy(AB);

  for LI := 0 to 15 do
  begin
    LBits := AA[LI];
    for LJ := 7 downto 0 do
    begin
      if (LBits and (1 shl LJ)) <> 0 then
      begin
        XorBlock(Result, LTmp);
      end;

      LLsb := (LTmp[15] and 1) <> 0;
      ShiftRight(LTmp);
      if LLsb then
      begin
        LTmp[0] := LTmp[0] xor Byte($E1);
      end;
    end;
  end;
end;

class procedure TTestGcmReorder.ShiftRight(const ABlock: TBytes);
var
  LI: Int32;
  LBit, LB: Byte;
begin
  LI := 0;
  LBit := 0;
  while True do
  begin
    LB := ABlock[LI];
    ABlock[LI] := (LB shr 1) or LBit;
    Inc(LI);
    if LI = 16 then
      Break;
    LBit := LB shl 7;
  end;
end;

procedure TTestGcmReorder.TestCombine;
var
  LCount: Int32;
  LA, LC, LGhashA, LGhashC, LGhashAC, LGhashCombine: TBytes;
begin
  for LCount := 0 to 9 do
  begin
    LA := RandomBytes(1000);
    LC := RandomBytes(1000);

    LGhashA := Ghash(LA, FEmpty);
    LGhashC := Ghash(FEmpty, LC);
    LGhashAC := Ghash(LA, LC);

    LGhashCombine := CombineGhash(LGhashA, Int64(System.Length(LA)) * 8,
      LGhashC, Int64(System.Length(LC)) * 8);

    if not AreEqual(LGhashAC, LGhashCombine) then
    begin
      Fail('TestCombine failed');
    end;
  end;
end;

procedure TTestGcmReorder.TestConcatAuth;
var
  LCount: Int32;
  LP, LA, LPA, LGhashP, LGhashA, LGhashPA, LGhashConcat: TBytes;
begin
  for LCount := 0 to 9 do
  begin
    LP := RandomBlocks(100);
    LA := RandomBytes(1000);
    LPA := TArrayUtilities.Concatenate<Byte>(LP, LA);

    LGhashP := Ghash(LP, FEmpty);
    LGhashA := Ghash(LA, FEmpty);
    LGhashPA := Ghash(LPA, FEmpty);
    LGhashConcat := ConcatAuthGhash(LGhashP, Int64(System.Length(LP)) * 8,
      LGhashA, Int64(System.Length(LA)) * 8);

    if not AreEqual(LGhashPA, LGhashConcat) then
    begin
      Fail('TestConcatAuth failed');
    end;
  end;
end;

procedure TTestGcmReorder.TestConcatCrypt;
var
  LCount: Int32;
  LP, LA, LPA, LGhashP, LGhashA, LGhashPA, LGhashConcat: TBytes;
begin
  for LCount := 0 to 9 do
  begin
    LP := RandomBlocks(100);
    LA := RandomBytes(1000);
    LPA := TArrayUtilities.Concatenate<Byte>(LP, LA);

    LGhashP := Ghash(FEmpty, LP);
    LGhashA := Ghash(FEmpty, LA);
    LGhashPA := Ghash(FEmpty, LPA);
    LGhashConcat := ConcatCryptGhash(LGhashP, Int64(System.Length(LP)) * 8,
      LGhashA, Int64(System.Length(LA)) * 8);

    if not AreEqual(LGhashPA, LGhashConcat) then
    begin
      Fail('TestConcatCrypt failed');
    end;
  end;
end;

procedure TTestGcmReorder.TestExp;
var
  LBuf1, LBuf2, LData, LExpected, LHa, LActual: TBytes;
  LPow: Int32;
  LTestPow: TCryptoLibInt64Array;
  LTestData: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LI, LJ: Int32;
begin
  System.SetLength(LBuf1, 16);
  LBuf1[0] := $80;

  System.SetLength(LBuf2, 16);

  for LPow := 0 to 99 do
  begin
    FExp.ExponentiateX(LPow, LBuf2);

    if not AreEqual(LBuf1, LBuf2) then
    begin
      Fail(Format('TestExp failed at pow %d', [LPow]));
    end;

    FMul.MultiplyH(LBuf1);
  end;

  LTestPow := TCryptoLibInt64Array.Create(10, 1, 8, 17, 24, 13, 2, 13, 2, 3);
  LTestData := TCryptoLibGenericArray<TCryptoLibByteArray>.Create(
    DecodeHex('9185848a877bd87ba071e281f476e8e7'),
    DecodeHex('697ce3052137d80745d524474fb6b290'),
    DecodeHex('2696fc47198bb23b11296e4f88720a17'),
    DecodeHex('01f2f0ead011a4ae0cf3572f1b76dd8e'),
    DecodeHex('a53060694a044e4b7fa1e661c5a7bb6b'),
    DecodeHex('39c0392e8b6b0e04a7565c85394c2c4c'),
    DecodeHex('519c362d502e07f2d8b7597a359a5214'),
    DecodeHex('5a527a393675705e19b2117f67695af4'),
    DecodeHex('27fc0901d1d332a53ba4d4386c2109d2'),
    DecodeHex('93ca9b57174aabedf8220e83366d7df6'));

  for LI := 0 to 9 do
  begin
    LData := System.Copy(LTestData[LI]);

    LExpected := System.Copy(LData);
    for LJ := 0 to LTestPow[LI] - 1 do
    begin
      FMul.MultiplyH(LExpected);
    end;

    System.SetLength(LHa, 16);
    FExp.ExponentiateX(LTestPow[LI], LHa);
    LActual := Multiply(LData, LHa);

    if not AreEqual(LExpected, LActual) then
    begin
      Fail(Format('TestExp data failed at index %d', [LI]));
    end;
  end;
end;

procedure TTestGcmReorder.TestMultiply;
var
  LExpected, LA, LB: TBytes;
  LCount: Int32;
begin
  LExpected := System.Copy(FH);
  FMul.MultiplyH(LExpected);

  if not AreEqual(LExpected, Multiply(FH, FH)) then
  begin
    Fail('TestMultiply H*H failed');
  end;

  for LCount := 0 to 9 do
  begin
    System.SetLength(LA, 16);
    FRandom.NextBytes(LA);

    System.SetLength(LB, 16);
    FRandom.NextBytes(LB);

    LExpected := System.Copy(LA);
    FMul.MultiplyH(LExpected);
    if not AreEqual(LExpected, Multiply(LA, FH)) then
    begin
      Fail('TestMultiply a*H failed');
    end;
    if not AreEqual(LExpected, Multiply(FH, LA)) then
    begin
      Fail('TestMultiply H*a failed');
    end;

    LExpected := System.Copy(LB);
    FMul.MultiplyH(LExpected);
    if not AreEqual(LExpected, Multiply(LB, FH)) then
    begin
      Fail('TestMultiply b*H failed');
    end;
    if not AreEqual(LExpected, Multiply(FH, LB)) then
    begin
      Fail('TestMultiply H*b failed');
    end;

    if not AreEqual(Multiply(LA, LB), Multiply(LB, LA)) then
    begin
      Fail('TestMultiply commutativity failed');
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestGcmReorder);
{$ELSE}
  RegisterTest(TTestGcmReorder.Suite);
{$ENDIF FPC}

end.
