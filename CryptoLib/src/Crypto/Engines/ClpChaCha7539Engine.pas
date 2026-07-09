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

unit ClpChaCha7539Engine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCipher,
  ClpIChaCha7539Engine,
  ClpChaChaEngine,
  ClpPack,
  ClpCryptoLibTypes;

resourcestring
  SInvalidKeySizeTwoFiftySix = '%s requires 256 bit key';
  SCounterExceeded = 'attempt to increase counter past 2^32';

type
  /// <summary>
  /// ChaCha20 per RFC 7539 (IETF): 96-bit nonce, 32-bit block counter (word 12).
  /// </summary>
  TChaCha7539Engine = class(TChaChaBaseEngine, IChaCha7539Engine, IStreamCipher)

  strict protected
    function GetAlgorithmName: String; override;
    function GetNonceSize: Int32; override;

    procedure AdvanceCounter(); override;
    procedure ResetCounter(); override;
    procedure SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray); override;

  public
    constructor Create();

  end;

implementation

{ TChaCha7539Engine }

constructor TChaCha7539Engine.Create;
begin
  inherited Create();
end;

function TChaCha7539Engine.GetAlgorithmName: String;
begin
  Result := 'ChaCha7539';
end;

function TChaCha7539Engine.GetNonceSize: Int32;
begin
  Result := 12;
end;

procedure TChaCha7539Engine.AdvanceCounter;
begin
  System.Inc(FEngineState[12]);
  if (FEngineState[12] = 0) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SCounterExceeded);
  end;
end;

procedure TChaCha7539Engine.ResetCounter;
begin
  FEngineState[12] := 0;
end;

procedure TChaCha7539Engine.SetKey(const AKeyBytes,
  AIvBytes: TCryptoLibByteArray);
begin
  if (AKeyBytes <> nil) then
  begin
    if (System.Length(AKeyBytes) <> 32) then
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidKeySizeTwoFiftySix,
        [AlgorithmName]);
    end;

    PackTauOrSigma(32, FEngineState);

    // Key
    TPack.LE_To_UInt32(AKeyBytes, 0, FEngineState, 4, 8);
  end;

  // IV
  TPack.LE_To_UInt32(AIvBytes, 0, FEngineState, 13, 3);
end;

end.
