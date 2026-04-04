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

unit ClpPkcs12ParametersGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIDigest,
  ClpICipherParameters,
  ClpIPkcs12ParametersGenerator,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpParameterUtilities,
  ClpPbeParametersGenerator,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// Generator for PBE derived keys and IVs as defined by Pkcs 12 V1.0.
  /// </summary>
  TPkcs12ParametersGenerator = class sealed(TPbeParametersGenerator,
    IPkcs12ParametersGenerator)

  public
    const
      KeyMaterial = 1;
      IVMaterial = 2;
      MacMaterial = 3;

  strict private
  var
    FDigest: IDigest;
    FU: Int32;
    FV: Int32;

    procedure Adjust(var AA: TCryptoLibByteArray; AOff: Int32;
      const AB: TCryptoLibByteArray);
    procedure RepeatFill(const AX, AZ: TCryptoLibByteArray);
    function GenerateDerivedKey(AIdByte: Byte; AN: Int32): TCryptoLibByteArray; overload;
    procedure GenerateDerivedKey(AIdByte: Byte; const ADKey: TCryptoLibByteArray); overload;

  public

    /// <summary>
    /// Construct a Pkcs 12 Parameters generator.
    /// </summary>
    /// <param name="ADigest">the digest to be used as the source of derived keys.</param>
    constructor Create(const ADigest: IDigest);

    function GenerateDerivedParameters(const AAlgorithm: String; AKeySize: Int32)
      : ICipherParameters; overload; override;

    function GenerateDerivedParameters(const AAlgorithm: String;
      AKeySize, AIvSize: Int32): ICipherParameters; overload; override;

    function GenerateDerivedMacParameters(AKeySize: Int32)
      : ICipherParameters; override;

  end;

implementation

{ TPkcs12ParametersGenerator }

procedure TPkcs12ParametersGenerator.Adjust(var AA: TCryptoLibByteArray;
  AOff: Int32; const AB: TCryptoLibByteArray);
var
  LX: UInt32;
  LI, LBLen: Int32;
begin
  LBLen := System.Length(AB);
  if LBLen = 0 then
    Exit;

  LX := UInt32(AB[LBLen - 1]) + UInt32(AA[AOff + LBLen - 1]) + 1;

  AA[AOff + LBLen - 1] := Byte(LX);
  LX := LX shr 8;

  for LI := LBLen - 2 downto 0 do
  begin
    LX := LX + UInt32(AB[LI]) + UInt32(AA[AOff + LI]);
    AA[AOff + LI] := Byte(LX);
    LX := LX shr 8;
  end;
end;

constructor TPkcs12ParametersGenerator.Create(const ADigest: IDigest);
begin
  inherited Create();
  FDigest := ADigest;
  FU := FDigest.GetDigestSize();
  FV := FDigest.GetByteLength();
end;

procedure TPkcs12ParametersGenerator.GenerateDerivedKey(AIdByte: Byte;
  const ADKey: TCryptoLibByteArray);
var
  LD, LS, LP, LI, LA, LB: TCryptoLibByteArray;
  LC, LIdx, LJ, JV, LCopyLen: Int32;
  LSaltEmpty, LPasswordEmpty: Boolean;
begin
  System.SetLength(LD, FV);
  TArrayUtilities.Fill<Byte>(LD, 0, System.Length(LD), Byte(AIdByte));

  LSaltEmpty := (FSalt = nil) or (System.Length(FSalt) = 0);
  LS := nil;
  if not LSaltEmpty then
  begin
    System.SetLength(LS, FV * ((System.Length(FSalt) + FV - 1) div FV));
    RepeatFill(FSalt, LS);
  end;

  LPasswordEmpty := (FPassword = nil) or (System.Length(FPassword) = 0);
  LP := nil;
  if not LPasswordEmpty then
  begin
    System.SetLength(LP, FV * ((System.Length(FPassword) + FV - 1) div FV));
    RepeatFill(FPassword, LP);
  end;

  LI := TArrayUtilities.Concatenate<Byte>(LS, LP);

  System.SetLength(LA, FU);
  System.SetLength(LB, FV);
  LC := (System.Length(ADKey) + FU - 1) div FU;

  for LIdx := 1 to LC do
  begin
    FDigest.BlockUpdate(LD, 0, System.Length(LD));
    FDigest.BlockUpdate(LI, 0, System.Length(LI));
    FDigest.DoFinal(LA, 0);

    for LJ := 1 to FIterationCount - 1 do
    begin
      FDigest.BlockUpdate(LA, 0, System.Length(LA));
      FDigest.DoFinal(LA, 0);
    end;

    RepeatFill(LA, LB);

    JV := 0;
    while JV < System.Length(LI) do
    begin
      Adjust(LI, JV, LB);
      JV := JV + FV;
    end;

    if LIdx = LC then
    begin
      LCopyLen := System.Length(ADKey) - ((LIdx - 1) * FU);
      if LCopyLen > 0 then
        System.Move(LA[0], ADKey[(LIdx - 1) * FU], LCopyLen * System.SizeOf(Byte));
    end
    else
      System.Move(LA[0], ADKey[(LIdx - 1) * FU], System.Length(LA) * System.SizeOf(Byte));
  end;
end;

function TPkcs12ParametersGenerator.GenerateDerivedKey(AIdByte: Byte;
  AN: Int32): TCryptoLibByteArray;
begin
  System.SetLength(Result, AN);
  GenerateDerivedKey(AIdByte, Result);
end;

function TPkcs12ParametersGenerator.GenerateDerivedParameters(
  const AAlgorithm: String; AKeySize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(Byte(KeyMaterial), LKeySize);
  Result := TParameterUtilities.CreateKeyParameter(AAlgorithm, LDKey, 0,
    LKeySize);
end;

function TPkcs12ParametersGenerator.GenerateDerivedParameters(
  const AAlgorithm: String; AKeySize, AIvSize: Int32): ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LIv: TCryptoLibByteArray;
  LKey: IKeyParameter;
  LKeySize, LIvSize: Int32;
begin
  LKeySize := AKeySize div 8;
  LIvSize := AIvSize div 8;

  LDKey := GenerateDerivedKey(Byte(KeyMaterial), LKeySize);
  LKey := TParameterUtilities.CreateKeyParameter(AAlgorithm, LDKey, 0,
    LKeySize);

  LIv := GenerateDerivedKey(Byte(IVMaterial), LIvSize);
  Result := TParametersWithIV.Create(LKey, LIv, 0, LIvSize);
end;

function TPkcs12ParametersGenerator.GenerateDerivedMacParameters(AKeySize: Int32)
  : ICipherParameters;
var
  LDKey: TCryptoLibByteArray;
  LKeySize: Int32;
begin
  LKeySize := AKeySize div 8;
  LDKey := GenerateDerivedKey(Byte(MacMaterial), LKeySize);
  Result := TKeyParameter.Create(LDKey, 0, LKeySize);
end;

procedure TPkcs12ParametersGenerator.RepeatFill(const AX, AZ: TCryptoLibByteArray);
var
  LLenX, LLenZ, LPos: Int32;
begin
  LLenX := System.Length(AX);
  LLenZ := System.Length(AZ);
  LPos := 0;
  while LPos < LLenZ - LLenX do
  begin
    System.Move(AX[0], AZ[LPos], LLenX * System.SizeOf(Byte));
    LPos := LPos + LLenX;
  end;
  if LLenZ - LPos > 0 then
    System.Move(AX[0], AZ[LPos], (LLenZ - LPos) * System.SizeOf(Byte));
end;

end.
