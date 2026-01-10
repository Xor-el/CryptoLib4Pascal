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

unit ClpRsaKeyGenerationParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIRsaKeyGenerationParameters,
  ClpKeyGenerationParameters,
  ClpISecureRandom,
  ClpCryptoLibTypes;

resourcestring
  SPublicExponentNil = 'publicExponent';
  SPublicExponentNotOdd = 'Public exponent must be an odd number';

type
  /// <summary>
  /// RSA key generation parameters.
  /// </summary>
  TRsaKeyGenerationParameters = class(TKeyGenerationParameters,
    IRsaKeyGenerationParameters)

  strict private
  const
    DefaultTests = 100;

  var
    FPublicExponent: TBigInteger;
    FCertainty: Int32;

  strict protected
    function GetPublicExponent: TBigInteger;
    function GetCertainty: Int32;

  public
    /// <summary>
    /// Create RSA key generation parameters.
    /// </summary>
    /// <param name="publicExponent">
    /// The public exponent for generated keys, typically 0x10001 (65537).
    /// </param>
    /// <param name="random">
    /// The random source for key generation.
    /// </param>
    /// <param name="strength">
    /// The key size in bits.
    /// </param>
    /// <param name="certainty">
    /// The certainty (number of iterations) for primality testing.
    /// </param>
    constructor Create(const publicExponent: TBigInteger;
      const random: ISecureRandom; strength, certainty: Int32);

    function Equals(const other: IRsaKeyGenerationParameters): Boolean;
      reintroduce; overload;
    function GetHashCode: {$IFDEF DELPHI}Int32;{$ELSE}PtrInt;{$ENDIF DELPHI} override;

    property PublicExponent: TBigInteger read GetPublicExponent;
    property Certainty: Int32 read GetCertainty;

  end;

implementation

{ TRsaKeyGenerationParameters }

constructor TRsaKeyGenerationParameters.Create(const publicExponent: TBigInteger;
  const random: ISecureRandom; strength, certainty: Int32);
begin
  inherited Create(random, strength);

  if not publicExponent.IsInitialized then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SPublicExponentNil);
  end;

  if not publicExponent.TestBit(0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SPublicExponentNotOdd);
  end;

  FPublicExponent := publicExponent;
  FCertainty := certainty;
end;

function TRsaKeyGenerationParameters.GetCertainty: Int32;
begin
  Result := FCertainty;
end;

function TRsaKeyGenerationParameters.GetPublicExponent: TBigInteger;
begin
  Result := FPublicExponent;
end;

function TRsaKeyGenerationParameters.Equals(const other: IRsaKeyGenerationParameters): Boolean;
begin
  if other = nil then
  begin
    Result := False;
    Exit;
  end;

  if (Self as IRsaKeyGenerationParameters) = other then
  begin
    Result := True;
    Exit;
  end;

  Result := (FCertainty = other.Certainty) and
    FPublicExponent.Equals(other.PublicExponent);
end;

function TRsaKeyGenerationParameters.GetHashCode: {$IFDEF DELPHI}Int32;{$ELSE}PtrInt;{$ENDIF DELPHI}
begin
  Result := FCertainty xor FPublicExponent.GetHashCode();
end;

end.
