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

unit ClpXSalsa20Engine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCipher,
  ClpSalsa20Engine,
  ClpIXSalsa20Engine,
  ClpPack,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SNullKeyReInit = '%s Doesn''t Support Re-Init with Null Key';
  SInvalidKeySize = '%s Requires a 256 bit Key';

type
  /// <summary>
  /// Implementation of Daniel J. Bernstein's XSalsa20 stream cipher - Salsa20 with an extended nonce.
  /// </summary>
  /// <remarks>
  /// XSalsa20 requires a 256 bit key, and a 192 bit nonce.
  /// </remarks>
  TXSalsa20Engine = class sealed(TSalsa20Engine, IXSalsa20Engine, IStreamCipher)

  strict protected
    function GetAlgorithmName: String; override;
    function GetNonceSize: Int32; override;
    /// <summary>
    /// XSalsa20 key generation: process 256 bit input key and 128 bits of the input nonce
    /// using a core Salsa20 function without input addition to produce 256 bit working key
    /// and use that with the remaining 64 bits of nonce to initialize a standard Salsa20 engine state.
    /// </summary>
    procedure SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray); override;

  end;

implementation

{ TXSalsa20Engine }

function TXSalsa20Engine.GetAlgorithmName: String;
begin
  Result := 'XSalsa20';
end;

function TXSalsa20Engine.GetNonceSize: Int32;
begin
  Result := 24;
end;

procedure TXSalsa20Engine.SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray);
var
  LHsalsa20Out: TCryptoLibUInt32Array;
begin
  if (AKeyBytes = nil) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SNullKeyReInit,
      [AlgorithmName]);
  end;

  if (System.Length(AKeyBytes) <> 32) then
  begin
    TArrayUtilities.Fill<Byte>(AKeyBytes, 0, System.Length(AKeyBytes), Byte(0));
    TArrayUtilities.Fill<Byte>(AIvBytes, 0, System.Length(AIvBytes), Byte(0));
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidKeySize,
      [AlgorithmName]);
  end;

  // Set key for HSalsa20
  Inherited SetKey(AKeyBytes, AIvBytes);

  // Pack next 64 bits of IV into engine state instead of counter
  TPack.LE_To_UInt32(AIvBytes, 8, FEngineState, 8, 2);

  // Process engine state to generate Salsa20 key
  System.SetLength(LHsalsa20Out, System.Length(FEngineState));
  SalsaCore(20, FEngineState, LHsalsa20Out);

  // Set new key, removing addition in last round of salsaCore
  FEngineState[1] := LHsalsa20Out[0] - FEngineState[0];
  FEngineState[2] := LHsalsa20Out[5] - FEngineState[5];
  FEngineState[3] := LHsalsa20Out[10] - FEngineState[10];
  FEngineState[4] := LHsalsa20Out[15] - FEngineState[15];

  FEngineState[11] := LHsalsa20Out[6] - FEngineState[6];
  FEngineState[12] := LHsalsa20Out[7] - FEngineState[7];
  FEngineState[13] := LHsalsa20Out[8] - FEngineState[8];
  FEngineState[14] := LHsalsa20Out[9] - FEngineState[9];

  // Last 64 bits of input IV
  TPack.LE_To_UInt32(AIvBytes, 16, FEngineState, 6, 2);

  TArrayUtilities.Fill<Byte>(AKeyBytes, 0, System.Length(AKeyBytes), Byte(0));
  TArrayUtilities.Fill<Byte>(AIvBytes, 0, System.Length(AIvBytes), Byte(0));
end;

end.
