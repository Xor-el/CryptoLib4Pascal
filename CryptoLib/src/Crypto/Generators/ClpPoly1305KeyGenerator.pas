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

unit ClpPoly1305KeyGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCipherKeyGenerator,
  ClpICipherKeyGenerator,
  ClpIPoly1305KeyGenerator,
  ClpIKeyGenerationParameters,
  ClpCryptoLibTypes;

resourcestring
  SPoly1305KeyMustBe256Bits = 'Poly1305 key must be 256 bits.';
  SInvalidRFormat = 'Invalid format for r portion of Poly1305 key.';

type
  TPoly1305KeyGenerator = class sealed(TCipherKeyGenerator,
    IPoly1305KeyGenerator, ICipherKeyGenerator)

  strict private
  const
    R_MASK_LOW_2 = Byte($FC);
    R_MASK_HIGH_4 = Byte($0F);

    class procedure CheckMask(AB: Byte; AMask: Byte); static; inline;

  strict protected
    procedure EngineInit(const AParameters: IKeyGenerationParameters); override;
    function EngineGenerateKey(): TCryptoLibByteArray; override;

  public
    class procedure Clamp(const AKey: TCryptoLibByteArray); static;
    class procedure CheckKey(const AKey: TCryptoLibByteArray); static;
  end;

implementation

{ TPoly1305KeyGenerator }

procedure TPoly1305KeyGenerator.EngineInit(
  const AParameters: IKeyGenerationParameters);
begin
  FRandom := AParameters.Random;
  FStrength := 32;
end;

function TPoly1305KeyGenerator.EngineGenerateKey: TCryptoLibByteArray;
begin
  Result := inherited EngineGenerateKey();
  Clamp(Result);
end;

class procedure TPoly1305KeyGenerator.Clamp(const AKey: TCryptoLibByteArray);
begin
  if System.Length(AKey) <> 32 then
    raise EArgumentCryptoLibException.CreateRes(@SPoly1305KeyMustBe256Bits);

  AKey[3] := AKey[3] and R_MASK_HIGH_4;
  AKey[7] := AKey[7] and R_MASK_HIGH_4;
  AKey[11] := AKey[11] and R_MASK_HIGH_4;
  AKey[15] := AKey[15] and R_MASK_HIGH_4;

  AKey[4] := AKey[4] and R_MASK_LOW_2;
  AKey[8] := AKey[8] and R_MASK_LOW_2;
  AKey[12] := AKey[12] and R_MASK_LOW_2;
end;

class procedure TPoly1305KeyGenerator.CheckKey(
  const AKey: TCryptoLibByteArray);
begin
  if System.Length(AKey) <> 32 then
    raise EArgumentCryptoLibException.CreateRes(@SPoly1305KeyMustBe256Bits);

  CheckMask(AKey[3], R_MASK_HIGH_4);
  CheckMask(AKey[7], R_MASK_HIGH_4);
  CheckMask(AKey[11], R_MASK_HIGH_4);
  CheckMask(AKey[15], R_MASK_HIGH_4);

  CheckMask(AKey[4], R_MASK_LOW_2);
  CheckMask(AKey[8], R_MASK_LOW_2);
  CheckMask(AKey[12], R_MASK_LOW_2);
end;

class procedure TPoly1305KeyGenerator.CheckMask(AB: Byte; AMask: Byte);
begin
  if (AB and (not AMask)) <> 0 then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidRFormat);
end;

end.
