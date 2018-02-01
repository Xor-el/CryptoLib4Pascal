unit ClpRandomDsaKCalculator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpISecureRandom,
  ClpIDsaKCalculator,
  ClpIRandomDsaKCalculator;

{$IFNDEF _FIXINSIGHT_}

resourcestring
  SUnSupportedOperation = 'Operation not Supported';
{$ENDIF}

type
  TRandomDsaKCalculator = class(TInterfacedObject, IDsaKCalculator,
    IRandomDsaKCalculator)

  strict private
    Fq: TBigInteger;
    Frandom: ISecureRandom;

    function GetIsDeterministic: Boolean; virtual;

  public
    property IsDeterministic: Boolean read GetIsDeterministic;
    procedure Init(const n: TBigInteger; const random: ISecureRandom);
      overload; virtual;
    procedure Init(n, d: TBigInteger; &message: TCryptoLibByteArray);
      overload; virtual;
    function NextK(): TBigInteger; virtual;
  end;

implementation

{ TRandomDsaKCalculator }

function TRandomDsaKCalculator.GetIsDeterministic: Boolean;
begin
  Result := False;
end;

procedure TRandomDsaKCalculator.Init(const n: TBigInteger;
  const random: ISecureRandom);
begin
  Fq := n;
  Frandom := random;
end;

{$IFNDEF _FIXINSIGHT_}

procedure TRandomDsaKCalculator.Init(n, d: TBigInteger;
  &message: TCryptoLibByteArray);
begin
  raise EInvalidOperationCryptoLibException.CreateRes(@SUnSupportedOperation);
end;
{$ENDIF}

function TRandomDsaKCalculator.NextK: TBigInteger;
var
  qBitLength: Int32;
  k: TBigInteger;
begin
  qBitLength := Fq.BitLength;

  repeat
    k := TBigInteger.Create(qBitLength, Frandom);
  until (not((k.SignValue < 1) or (k.CompareTo(Fq) >= 0)));

  Result := k;

end;

end.
