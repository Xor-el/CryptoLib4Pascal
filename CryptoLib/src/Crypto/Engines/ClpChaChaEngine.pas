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

unit ClpChaChaEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIStreamCipher,
  ClpIChaChaEngine,
  ClpSalsa20Engine,
  ClpPack,
  ClpCryptoLibTypes;

resourcestring
  SChaChaStateWords = 'ChaCha state must be at least 16 UInt32 values';
  SChaChaOut64 = 'ChaCha key stream output must be at least 64 bytes';
  SRoundsEven = 'Number of Rounds Must be Even';

type

  /// <summary>
  /// Implementation of Daniel J. Bernstein's ChaCha stream cipher.
  /// </summary>
  TChaChaEngine = class(TSalsa20Engine, IChaChaEngine, IStreamCipher)

  strict protected
    function GetAlgorithmName: String; override;

    procedure AdvanceCounter(); override;
    procedure ResetCounter(); override;
    procedure SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray); override;
    procedure GenerateKeyStream(const AOutput: TCryptoLibByteArray); override;

  public
    /// <summary>
    /// Creates a 20 rounds ChaCha engine.
    /// </summary>
    constructor Create(); overload;
    /// <summary>
    /// Creates a ChaCha engine with a specific number of rounds.
    /// </summary>
    /// <param name="ARounds">the number of rounds (must be an even number).</param>
    constructor Create(ARounds: Int32); overload;

    class procedure ChaChaCore(ARounds: Int32;
      const AInput: TCryptoLibUInt32Array;
      const AOutput: TCryptoLibByteArray); static;

  end;

implementation

{ TChaChaEngine }

procedure TChaChaEngine.AdvanceCounter;
begin
  System.Inc(FEngineState[12]);
  if (FEngineState[12] = 0) then
  begin
    System.Inc(FEngineState[13]);
  end;
end;

class procedure TChaChaEngine.ChaChaCore(ARounds: Int32;
  const AInput: TCryptoLibUInt32Array; const AOutput: TCryptoLibByteArray);
var
  LX00, LX01, LX02, LX03, LX04, LX05, LX06, LX07, LX08, LX09, LX10, LX11, LX12, LX13, LX14,
    LX15: UInt32;
  LIdx: Int32;
begin
  if (System.Length(AInput) < 16) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SChaChaStateWords);
  end;
  if (System.Length(AOutput) < 64) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SChaChaOut64);
  end;
  if ((ARounds mod 2) <> 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SRoundsEven);
  end;

  LX00 := AInput[0];
  LX01 := AInput[1];
  LX02 := AInput[2];
  LX03 := AInput[3];
  LX04 := AInput[4];
  LX05 := AInput[5];
  LX06 := AInput[6];
  LX07 := AInput[7];
  LX08 := AInput[8];
  LX09 := AInput[9];
  LX10 := AInput[10];
  LX11 := AInput[11];
  LX12 := AInput[12];
  LX13 := AInput[13];
  LX14 := AInput[14];
  LX15 := AInput[15];

  LIdx := ARounds;
  while LIdx > 0 do
  begin
    System.Inc(LX00, LX04);
    LX12 := R(LX12 xor LX00, 16);
    System.Inc(LX01, LX05);
    LX13 := R(LX13 xor LX01, 16);
    System.Inc(LX02, LX06);
    LX14 := R(LX14 xor LX02, 16);
    System.Inc(LX03, LX07);
    LX15 := R(LX15 xor LX03, 16);

    System.Inc(LX08, LX12);
    LX04 := R(LX04 xor LX08, 12);
    System.Inc(LX09, LX13);
    LX05 := R(LX05 xor LX09, 12);
    System.Inc(LX10, LX14);
    LX06 := R(LX06 xor LX10, 12);
    System.Inc(LX11, LX15);
    LX07 := R(LX07 xor LX11, 12);

    System.Inc(LX00, LX04);
    LX12 := R(LX12 xor LX00, 8);
    System.Inc(LX01, LX05);
    LX13 := R(LX13 xor LX01, 8);
    System.Inc(LX02, LX06);
    LX14 := R(LX14 xor LX02, 8);
    System.Inc(LX03, LX07);
    LX15 := R(LX15 xor LX03, 8);

    System.Inc(LX08, LX12);
    LX04 := R(LX04 xor LX08, 7);
    System.Inc(LX09, LX13);
    LX05 := R(LX05 xor LX09, 7);
    System.Inc(LX10, LX14);
    LX06 := R(LX06 xor LX10, 7);
    System.Inc(LX11, LX15);
    LX07 := R(LX07 xor LX11, 7);

    System.Inc(LX00, LX05);
    LX15 := R(LX15 xor LX00, 16);
    System.Inc(LX01, LX06);
    LX12 := R(LX12 xor LX01, 16);
    System.Inc(LX02, LX07);
    LX13 := R(LX13 xor LX02, 16);
    System.Inc(LX03, LX04);
    LX14 := R(LX14 xor LX03, 16);

    System.Inc(LX10, LX15);
    LX05 := R(LX05 xor LX10, 12);
    System.Inc(LX11, LX12);
    LX06 := R(LX06 xor LX11, 12);
    System.Inc(LX08, LX13);
    LX07 := R(LX07 xor LX08, 12);
    System.Inc(LX09, LX14);
    LX04 := R(LX04 xor LX09, 12);

    System.Inc(LX00, LX05);
    LX15 := R(LX15 xor LX00, 8);
    System.Inc(LX01, LX06);
    LX12 := R(LX12 xor LX01, 8);
    System.Inc(LX02, LX07);
    LX13 := R(LX13 xor LX02, 8);
    System.Inc(LX03, LX04);
    LX14 := R(LX14 xor LX03, 8);

    System.Inc(LX10, LX15);
    LX05 := R(LX05 xor LX10, 7);
    System.Inc(LX11, LX12);
    LX06 := R(LX06 xor LX11, 7);
    System.Inc(LX08, LX13);
    LX07 := R(LX07 xor LX08, 7);
    System.Inc(LX09, LX14);
    LX04 := R(LX04 xor LX09, 7);

    System.Dec(LIdx, 2);
  end;

  TPack.UInt32_To_LE(LX00 + AInput[0], AOutput, 0);
  TPack.UInt32_To_LE(LX01 + AInput[1], AOutput, 4);
  TPack.UInt32_To_LE(LX02 + AInput[2], AOutput, 8);
  TPack.UInt32_To_LE(LX03 + AInput[3], AOutput, 12);
  TPack.UInt32_To_LE(LX04 + AInput[4], AOutput, 16);
  TPack.UInt32_To_LE(LX05 + AInput[5], AOutput, 20);
  TPack.UInt32_To_LE(LX06 + AInput[6], AOutput, 24);
  TPack.UInt32_To_LE(LX07 + AInput[7], AOutput, 28);
  TPack.UInt32_To_LE(LX08 + AInput[8], AOutput, 32);
  TPack.UInt32_To_LE(LX09 + AInput[9], AOutput, 36);
  TPack.UInt32_To_LE(LX10 + AInput[10], AOutput, 40);
  TPack.UInt32_To_LE(LX11 + AInput[11], AOutput, 44);
  TPack.UInt32_To_LE(LX12 + AInput[12], AOutput, 48);
  TPack.UInt32_To_LE(LX13 + AInput[13], AOutput, 52);
  TPack.UInt32_To_LE(LX14 + AInput[14], AOutput, 56);
  TPack.UInt32_To_LE(LX15 + AInput[15], AOutput, 60);

end;

constructor TChaChaEngine.Create;
begin
  Inherited Create();
end;

constructor TChaChaEngine.Create(ARounds: Int32);
begin
  Inherited Create(ARounds);
end;

procedure TChaChaEngine.GenerateKeyStream(const AOutput: TCryptoLibByteArray);
begin
  ChaChaCore(FRounds, FEngineState, AOutput);
end;

function TChaChaEngine.GetAlgorithmName: String;
begin
  Result := Format('ChaCha%d', [FRounds]);
end;

procedure TChaChaEngine.ResetCounter;
begin
  FEngineState[12] := 0;
  FEngineState[13] := 0;
end;

procedure TChaChaEngine.SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray);
begin
  if (AKeyBytes <> nil) then
  begin
    if not(System.Length(AKeyBytes) in [16, 32]) then
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidKeySize,
        [AlgorithmName]);
    end;

    PackTauOrSigma(System.Length(AKeyBytes), FEngineState, 0);

    // Key
    TPack.LE_To_UInt32(AKeyBytes, 0, FEngineState, 4, 4);
    TPack.LE_To_UInt32(AKeyBytes, System.Length(AKeyBytes) - 16, FEngineState, 8, 4);
  end;

  // IV
  TPack.LE_To_UInt32(AIvBytes, 0, FEngineState, 14, 2);
end;

end.
