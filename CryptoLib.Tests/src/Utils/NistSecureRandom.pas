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

unit NistSecureRandom;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpSecureRandom,
  ClpCipherUtilities,
  ClpIBufferedCipher,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpCryptoLibTypes;

type
  TNistSecureRandom = class(TSecureRandom)
  strict private
  var
    FSeed: TCryptoLibByteArray;
    FPersonalization: TCryptoLibByteArray;
    FKey: TCryptoLibByteArray;
    FV: TCryptoLibByteArray;
    procedure AES256_ECB(const AKey, ACtr: TCryptoLibByteArray;
      const ABuffer: TCryptoLibByteArray; AStartPosition: Int32);
    procedure AES256_CTR_DRBG_Update(const AEntropyInput: TCryptoLibByteArray;
      var AKey, AV: TCryptoLibByteArray);
    procedure RandomBytesInit(const AEntropyInput, APersonalization: TCryptoLibByteArray;
      AStrength: Int32);
    procedure InitStrength(AStrength: Int32);
  public
    constructor Create(const ASeed, APersonalization: TCryptoLibByteArray);
    procedure NextBytes(const ABuf: TCryptoLibByteArray); overload; override;
    procedure NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32); overload; override;
  end;

implementation

{ TNistSecureRandom }

procedure TNistSecureRandom.AES256_ECB(const AKey, ACtr: TCryptoLibByteArray;
  const ABuffer: TCryptoLibByteArray; AStartPosition: Int32);
var
  LCipher: IBufferedCipher;
begin
  LCipher := TCipherUtilities.GetCipher('AES/ECB/NOPADDING');
  LCipher.Init(True, TKeyParameter.Create(AKey) as IKeyParameter);
  LCipher.DoFinal(ACtr, 0, System.Length(ACtr), ABuffer, AStartPosition);
end;

procedure TNistSecureRandom.AES256_CTR_DRBG_Update(const AEntropyInput: TCryptoLibByteArray;
  var AKey, AV: TCryptoLibByteArray);
var
  LTmp: TCryptoLibByteArray;
  LI, LJ: Int32;
begin
  System.SetLength(LTmp, 48);
  for LI := 0 to 2 do
  begin
    for LJ := 15 downto 0 do
    begin
      System.Inc(AV[LJ]);
      if AV[LJ] <> 0 then
        Break;
    end;
    AES256_ECB(AKey, AV, LTmp, 16 * LI);
  end;
  if AEntropyInput <> nil then
  begin
    for LI := 0 to 47 do
      LTmp[LI] := LTmp[LI] xor AEntropyInput[LI];
  end;
  System.Move(LTmp[0], AKey[0], System.Length(AKey));
  System.Move(LTmp[32], AV[0], System.Length(AV));
end;

constructor TNistSecureRandom.Create(const ASeed, APersonalization: TCryptoLibByteArray);
begin
  inherited Create(nil);
  FSeed := ASeed;
  FPersonalization := APersonalization;
  InitStrength(256);
end;

procedure TNistSecureRandom.InitStrength(AStrength: Int32);
begin
  RandomBytesInit(FSeed, FPersonalization, AStrength);
end;

procedure TNistSecureRandom.NextBytes(const ABuf: TCryptoLibByteArray);
begin
  NextBytes(ABuf, 0, System.Length(ABuf));
end;

procedure TNistSecureRandom.NextBytes(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32);
var
  LBlock: TCryptoLibByteArray;
  LI, LJ: Int32;
begin
  System.SetLength(LBlock, 16);
  LI := 0;
  while ALen > 0 do
  begin
    for LJ := 15 downto 0 do
    begin
      System.Inc(FV[LJ]);
      if FV[LJ] <> 0 then
        Break;
    end;
    AES256_ECB(FKey, FV, LBlock, 0);
    if ALen > 15 then
    begin
      System.Move(LBlock[0], ABuf[AOff + LI], 16);
      System.Inc(LI, 16);
      System.Dec(ALen, 16);
    end
    else
    begin
      System.Move(LBlock[0], ABuf[AOff + LI], ALen);
      ALen := 0;
    end;
  end;
  AES256_CTR_DRBG_Update(nil, FKey, FV);
end;

procedure TNistSecureRandom.RandomBytesInit(const AEntropyInput,
  APersonalization: TCryptoLibByteArray; AStrength: Int32);
var
  LSeedMaterial: TCryptoLibByteArray;
  LI: Int32;
begin
  System.SetLength(LSeedMaterial, 48);
  System.Move(AEntropyInput[0], LSeedMaterial[0], System.Length(LSeedMaterial));
  if APersonalization <> nil then
  begin
    for LI := 0 to 47 do
      LSeedMaterial[LI] := LSeedMaterial[LI] xor APersonalization[LI];
  end;
  System.SetLength(FKey, 32);
  System.SetLength(FV, 16);
  AES256_CTR_DRBG_Update(LSeedMaterial, FKey, FV);
end;

end.
