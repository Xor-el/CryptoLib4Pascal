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

unit ClpDrbgUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpIDigest,
  ClpIMac,
  ClpPack,
  ClpCryptoLibComparers;

type
  TDrbgUtilities = class sealed(TObject)
  strict private
    class var
      FMaxSecurityStrengths: TDictionary<string, Int32>;

    class constructor Create;
    class destructor Destroy;
  public
    class function GetMaxSecurityStrength(const ADigest: IDigest): Int32; overload; static;
    class function GetMaxSecurityStrength(const AMac: IMac): Int32; overload; static;

    class procedure HashDF(const ADigest: IDigest;
      const ASeedMaterial: TCryptoLibByteArray; ASeedLength: Int32;
      const AOutput: TCryptoLibByteArray); static;
  end;

implementation

{ TDrbgUtilities }

class constructor TDrbgUtilities.Create;
begin
  FMaxSecurityStrengths := TDictionary<string, Int32>.Create(
    TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
  FMaxSecurityStrengths.Add('SHA-1', 128);
  FMaxSecurityStrengths.Add('SHA-224', 192);
  FMaxSecurityStrengths.Add('SHA-256', 256);
  FMaxSecurityStrengths.Add('SHA-384', 256);
  FMaxSecurityStrengths.Add('SHA-512', 256);
  FMaxSecurityStrengths.Add('SHA-512/224', 192);
  FMaxSecurityStrengths.Add('SHA-512/256', 256);
end;

class destructor TDrbgUtilities.Destroy;
begin
  FMaxSecurityStrengths.Free;
end;

class function TDrbgUtilities.GetMaxSecurityStrength(const ADigest: IDigest): Int32;
begin
  Result := FMaxSecurityStrengths[ADigest.AlgorithmName];
end;

class function TDrbgUtilities.GetMaxSecurityStrength(const AMac: IMac): Int32;
var
  LName, LBase: string;
  LSlash: Int32;
begin
  LName := AMac.AlgorithmName;
  LSlash := Pos('/', LName);
  if LSlash > 0 then
    LBase := Copy(LName, 1, LSlash - 1)
  else
    LBase := LName;
  Result := FMaxSecurityStrengths[LBase];
end;

class procedure TDrbgUtilities.HashDF(const ADigest: IDigest;
  const ASeedMaterial: TCryptoLibByteArray; ASeedLength: Int32;
  const AOutput: TCryptoLibByteArray);
var
  LOutputLength, LDigestSize, LLen, LCounter, LI, LBytesToCopy: Int32;
  LDig, LHeader: TCryptoLibByteArray;
  LCarry, LB: UInt32;
begin
  LOutputLength := (ASeedLength + 7) div 8;
  LDigestSize := ADigest.GetDigestSize;
  LLen := LOutputLength div LDigestSize;
  LCounter := 1;
  System.SetLength(LDig, LDigestSize);
  System.SetLength(LHeader, 5);
  TPack.UInt32_To_BE(UInt32(ASeedLength), LHeader, 1);

  for LI := 0 to LLen do
  begin
    LHeader[0] := Byte(LCounter);
    ADigest.BlockUpdate(LHeader, 0, System.Length(LHeader));
    ADigest.BlockUpdate(ASeedMaterial, 0, System.Length(ASeedMaterial));
    ADigest.DoFinal(LDig, 0);
    LBytesToCopy := LDigestSize;
    if LBytesToCopy > LOutputLength - LI * LDigestSize then
      LBytesToCopy := LOutputLength - LI * LDigestSize;
    if LBytesToCopy > 0 then
      System.Move(LDig[0], AOutput[LI * LDigestSize], LBytesToCopy * System.SizeOf(Byte));
    Inc(LCounter);
  end;

  if (ASeedLength mod 8) <> 0 then
  begin
    LCarry := 0;
    for LI := 0 to LOutputLength - 1 do
    begin
      LB := AOutput[LI];
      AOutput[LI] := Byte((LB shr (8 - (ASeedLength mod 8))) or (LCarry shl (ASeedLength mod 8)));
      LCarry := LB;
    end;
  end;
end;

end.
