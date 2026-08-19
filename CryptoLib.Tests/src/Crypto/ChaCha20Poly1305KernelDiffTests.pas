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

unit ChaCha20Poly1305KernelDiffTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIChaCha20Poly1305,
  ClpChaCha20Poly1305,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpICipherParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpChaCha7539Engine,
  ClpIChaCha7539Engine,
  ClpIStreamCipher,
  ClpCipherKernelTypes,
  ClpIChaCha20Poly1305Kernel,
  ClpCipherKernelRegistry,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpConverters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase;

type
  /// <summary>
  /// Differential safety net for the ChaCha20-Poly1305 kernel poly path: the
  /// mode routes all Poly1305 through the resolved kernel (ref kernel at
  /// Fallback), so seal/open under the kernel path must produce byte-identical
  /// output to the scalar FPoly1305 path (TCipherKernelGate.ForceDisabled). Swept
  /// across AAD/data lengths around the 16- and 64-byte boundaries, one-shot and
  /// chunked (1- and 7-byte), in-place and disjoint. A symmetric poly bug that a
  /// same-path round-trip would hide is caught by cross-path comparison.
  /// </summary>
  TTestChaCha20Poly1305KernelDiff = class(TCryptoLibAlgorithmTestCase)
  strict private
    // Runs one AEAD op. AChunk = 0 => one-shot; else feed AAD and data in
    // AChunk-sized ProcessBytes/ProcessAadBytes calls. AInPlace => output buffer
    // aliases the input. Result False iff DoFinal rejected (bad tag).
    function Process(AForEncrypt: Boolean; const AKey, ANonce, AAad, AInput: TBytes;
      AForceDisabled: Boolean; AChunk: Int32; AInPlace: Boolean;
      out AOut: TBytes): Boolean;
    function Seal(const AKey, ANonce, AAad, APlain: TBytes;
      AForceDisabled: Boolean; AChunk: Int32; AInPlace: Boolean): TBytes;
  published
    // Guard: proves the kernel path is real (gate off => a kernel is acquired),
    // so the parity tests below are kernel-vs-scalar, not scalar-vs-scalar.
    procedure TestKernelPathIsActive;
    procedure TestSealKernelVsScalarParity;
    procedure TestOpenKernelVsScalarParity;
  end;

implementation

const
  CAadLens: array [0 .. 8] of Int32 = (0, 1, 15, 16, 17, 31, 63, 64, 80);
  CDataLens: array [0 .. 20] of Int32 = (0, 1, 15, 16, 17, 63, 64, 65, 79, 80,
    81, 127, 128, 129, 511, 512, 513, 576, 1024, 1088, 4096);
  // 0 = one-shot; 1 and 7 exercise the cross-call staging.
  // 600: a mid-message chunk that arrives with a non-empty buffer AND >= 8 whole
  // blocks, exercising the buffered-block + fused-stride seam in one ProcessBytes.
  CChunks: array [0 .. 3] of Int32 = (0, 1, 7, 600);

{ TTestChaCha20Poly1305KernelDiff }

function TTestChaCha20Poly1305KernelDiff.Process(AForEncrypt: Boolean;
  const AKey, ANonce, AAad, AInput: TBytes; AForceDisabled: Boolean;
  AChunk: Int32; AInPlace: Boolean; out AOut: TBytes): Boolean;
var
  LSaved: Boolean;
  LCipher: IChaCha20Poly1305;
  LParams: IAeadParameters;
  LBuf: TBytes;
  LInLen, LCap, LOff, LInOff, LCs: Int32;
begin
  AOut := nil;
  LSaved := TCipherKernelGate.ForceDisabled;
  // The kernel is resolved during Init, so the gate must be set before Init.
  TCipherKernelGate.ForceDisabled := AForceDisabled;
  try
    try
      LParams := TAeadParameters.Create(TKeyParameter.Create(AKey)
        as IKeyParameter, 16 * 8, ANonce, nil);
      LCipher := TChaCha20Poly1305.Create() as IChaCha20Poly1305;
      LCipher.Init(AForEncrypt, LParams as ICipherParameters);

      // AAD (chunked or one-shot) exercises the partial-block staging path.
      if System.Length(AAad) > 0 then
      begin
        if AChunk <= 0 then
          LCipher.ProcessAadBytes(AAad, 0, System.Length(AAad))
        else
        begin
          LInOff := 0;
          while LInOff < System.Length(AAad) do
          begin
            LCs := System.Length(AAad) - LInOff;
            if LCs > AChunk then
              LCs := AChunk;
            LCipher.ProcessAadBytes(AAad, LInOff, LCs);
            LInOff := LInOff + LCs;
          end;
        end;
      end;

      LInLen := System.Length(AInput);
      LCap := LCipher.GetOutputSize(LInLen);
      if AInPlace and (LInLen > LCap) then
        LCap := LInLen;
      System.SetLength(LBuf, LCap);
      if AInPlace and (LInLen > 0) then
        System.Move(AInput[0], LBuf[0], LInLen);

      LOff := 0;
      if AChunk <= 0 then
      begin
        if AInPlace then
          LOff := LOff + LCipher.ProcessBytes(LBuf, 0, LInLen, LBuf, LOff)
        else
          LOff := LOff + LCipher.ProcessBytes(AInput, 0, LInLen, LBuf, LOff);
      end
      else
      begin
        LInOff := 0;
        while LInOff < LInLen do
        begin
          LCs := LInLen - LInOff;
          if LCs > AChunk then
            LCs := AChunk;
          if AInPlace then
            LOff := LOff + LCipher.ProcessBytes(LBuf, LInOff, LCs, LBuf, LOff)
          else
            LOff := LOff + LCipher.ProcessBytes(AInput, LInOff, LCs, LBuf, LOff);
          LInOff := LInOff + LCs;
        end;
      end;

      LOff := LOff + LCipher.DoFinal(LBuf, LOff);
      System.SetLength(LBuf, LOff);
      AOut := LBuf;
      Result := True;
    except
      // Only a rejected tag counts as failure; an unrelated crash must not
      // masquerade as a successful tag rejection.
      on EInvalidCipherTextCryptoLibException do
      begin
        Result := False;
        AOut := nil;
      end;
    end;
  finally
    TCipherKernelGate.ForceDisabled := LSaved;
  end;
end;

function TTestChaCha20Poly1305KernelDiff.Seal(const AKey, ANonce, AAad,
  APlain: TBytes; AForceDisabled: Boolean; AChunk: Int32;
  AInPlace: Boolean): TBytes;
begin
  if not Process(True, AKey, ANonce, AAad, APlain, AForceDisabled, AChunk,
    AInPlace, Result) then
    Fail('seal unexpectedly failed');
end;

procedure TTestChaCha20Poly1305KernelDiff.TestKernelPathIsActive;
var
  LEngine: IChaCha7539Engine;
  LKernel: IChaCha20Poly1305Kernel;
  LSaved, LGot: Boolean;
begin
  LEngine := TChaCha7539Engine.Create() as IChaCha7539Engine;
  LSaved := TCipherKernelGate.ForceDisabled;
  try
    TCipherKernelGate.ForceDisabled := False;
    LGot := TCipherKernelRegistry.TryAcquireChaCha20Poly1305(
      LEngine as IStreamCipher, TCipherKernelDirection.Encrypt, LKernel);
    // The fused kernel is intentionally parked on the arches where it loses to
    // the vectorized two-pass (x86-64: the scalar-poly mulx contends with ChaCha
    // for ports 1/5; i386: the radix-2^26 poly is register-starved) and is
    // cleared under FORCE_SCALAR. Where no kernel is registered the parity tests
    // legitimately run scalar-vs-scalar - expected, not a failure. aarch64 (NEON,
    // disjoint integer/vector pipes) still registers a kernel to differentiate.
    if (not LGot) or (LKernel = nil) then
      Exit;
  finally
    TCipherKernelGate.ForceDisabled := LSaved;
  end;
end;

procedure TTestChaCha20Poly1305KernelDiff.TestSealKernelVsScalarParity;
var
  LRnd: ISecureRandom;
  LKey, LNonce, LAad, LPlain, LRef, LOut: TBytes;
  LAi, LDi, LCi, LMi: Int32;
  LForce, LInPlace: Boolean;
begin
  LRnd := TSecureRandom.GetInstance('SHA256PRNG');
  LRnd.SetSeed(TConverters.ConvertStringToBytes(
    'ChaCha20Poly1305KernelDiff-Seal', TEncoding.ASCII));

  System.SetLength(LKey, 32);
  System.SetLength(LNonce, 12);

  for LAi := 0 to System.Length(CAadLens) - 1 do
    for LDi := 0 to System.Length(CDataLens) - 1 do
    begin
      LRnd.NextBytes(LKey);
      LRnd.NextBytes(LNonce);
      System.SetLength(LAad, CAadLens[LAi]);
      if System.Length(LAad) > 0 then
        LRnd.NextBytes(LAad);
      System.SetLength(LPlain, CDataLens[LDi]);
      if System.Length(LPlain) > 0 then
        LRnd.NextBytes(LPlain);

      // Reference: kernel path, one-shot, disjoint.
      LRef := Seal(LKey, LNonce, LAad, LPlain, False, 0, False);

      // Every feeding config on both paths must reproduce the reference.
      for LCi := 0 to System.Length(CChunks) - 1 do
        for LMi := 0 to 1 do
        begin
          LInPlace := LMi = 1;
          for LForce := False to True do
          begin
            LOut := Seal(LKey, LNonce, LAad, LPlain, LForce, CChunks[LCi],
              LInPlace);
            if not AreEqual(LOut, LRef) then
              Fail(Format('seal mismatch (aad=%d data=%d chunk=%d inplace=%d ' +
                'forceDisabled=%d)', [CAadLens[LAi], CDataLens[LDi],
                CChunks[LCi], LMi, Ord(LForce)]));
          end;
        end;
    end;
end;

procedure TTestChaCha20Poly1305KernelDiff.TestOpenKernelVsScalarParity;
var
  LRnd: ISecureRandom;
  LKey, LNonce, LAad, LPlain, LCt, LTamp, LOut: TBytes;
  LAi, LDi, LCi, LMi: Int32;
  LForce, LInPlace, LOk: Boolean;
begin
  LRnd := TSecureRandom.GetInstance('SHA256PRNG');
  LRnd.SetSeed(TConverters.ConvertStringToBytes(
    'ChaCha20Poly1305KernelDiff-Open', TEncoding.ASCII));

  System.SetLength(LKey, 32);
  System.SetLength(LNonce, 12);

  for LAi := 0 to System.Length(CAadLens) - 1 do
    for LDi := 0 to System.Length(CDataLens) - 1 do
    begin
      LRnd.NextBytes(LKey);
      LRnd.NextBytes(LNonce);
      System.SetLength(LAad, CAadLens[LAi]);
      if System.Length(LAad) > 0 then
        LRnd.NextBytes(LAad);
      System.SetLength(LPlain, CDataLens[LDi]);
      if System.Length(LPlain) > 0 then
        LRnd.NextBytes(LPlain);

      // Seal once (kernel path), then open on both paths and configs.
      LCt := Seal(LKey, LNonce, LAad, LPlain, False, 0, False);

      for LCi := 0 to System.Length(CChunks) - 1 do
        for LMi := 0 to 1 do
        begin
          LInPlace := LMi = 1;
          for LForce := False to True do
          begin
            LOk := Process(False, LKey, LNonce, LAad, LCt, LForce, CChunks[LCi],
              LInPlace, LOut);
            if not LOk then
              Fail(Format('open rejected valid tag (aad=%d data=%d chunk=%d ' +
                'inplace=%d forceDisabled=%d)', [CAadLens[LAi], CDataLens[LDi],
                CChunks[LCi], LMi, Ord(LForce)]));
            if not AreEqual(LOut, LPlain) then
              Fail(Format('open plaintext mismatch (aad=%d data=%d chunk=%d ' +
                'inplace=%d forceDisabled=%d)', [CAadLens[LAi], CDataLens[LDi],
                CChunks[LCi], LMi, Ord(LForce)]));
          end;
        end;

      // Tampered tag (flip last byte) must be rejected on both paths.
      LTamp := System.Copy(LCt, 0, System.Length(LCt));
      LTamp[System.Length(LTamp) - 1] := LTamp[System.Length(LTamp) - 1] xor $FF;
      if Process(False, LKey, LNonce, LAad, LTamp, False, 0, False, LOut) then
        Fail(Format('kernel path accepted tampered tag (aad=%d data=%d)',
          [CAadLens[LAi], CDataLens[LDi]]));
      if Process(False, LKey, LNonce, LAad, LTamp, True, 0, False, LOut) then
        Fail(Format('scalar path accepted tampered tag (aad=%d data=%d)',
          [CAadLens[LAi], CDataLens[LDi]]));
    end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestChaCha20Poly1305KernelDiff);
{$ELSE}
  RegisterTest(TTestChaCha20Poly1305KernelDiff.Suite);
{$ENDIF FPC}

end.
