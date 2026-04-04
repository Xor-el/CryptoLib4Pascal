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

unit ClpTables1kGcmExponentiator;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpBitOperations,
  ClpIGcmExponentiator,
  ClpGcmUtilities,
  ClpCryptoLibTypes;

type
  TTables1kGcmExponentiator = class(TInterfacedObject, IGcmExponentiator)
  strict private
    FLookupPowX2: TList<TFieldElement>;

    procedure EnsureAvailable(ABit: Int32);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Init(const AX: TCryptoLibByteArray);
    procedure ExponentiateX(APow: Int64; const AOutput: TCryptoLibByteArray);
  end;

implementation

{ TTables1kGcmExponentiator }

constructor TTables1kGcmExponentiator.Create;
begin
  inherited Create;
  FLookupPowX2 := TList<TFieldElement>.Create;
  FLookupPowX2.Capacity := 8;
end;

destructor TTables1kGcmExponentiator.Destroy;
begin
  FLookupPowX2.Free;
  inherited Destroy;
end;

procedure TTables1kGcmExponentiator.Init(const AX: TCryptoLibByteArray);
var
  LY: TFieldElement;
begin
  TGcmUtilities.AsFieldElement(AX, LY);
  if FLookupPowX2.Count > 0 then
  begin
    if (LY.N0 = FLookupPowX2[0].N0) and (LY.N1 = FLookupPowX2[0].N1) then
      Exit;
  end;

  FLookupPowX2.Clear;
  FLookupPowX2.Add(LY);
end;

procedure TTables1kGcmExponentiator.ExponentiateX(APow: Int64; const AOutput: TCryptoLibByteArray);
var
  LY, LPowX2: TFieldElement;
  LBit: Int32;
begin
  TGcmUtilities.One(LY);
  LBit := 0;
  while APow > 0 do
  begin
    if (APow and Int64(1)) <> 0 then
    begin
      EnsureAvailable(LBit);
      LPowX2 := FLookupPowX2[LBit];
      TGcmUtilities.Multiply(LY, LPowX2);
    end;
    System.Inc(LBit);
    APow := TBitOperations.Asr64(APow, 1);
  end;

  TGcmUtilities.AsBytes(LY, AOutput);
end;

procedure TTables1kGcmExponentiator.EnsureAvailable(ABit: Int32);
var
  LCount: Int32;
  LPowX2: TFieldElement;
begin
  LCount := FLookupPowX2.Count;
  if LCount <= ABit then
  begin
    LPowX2 := FLookupPowX2[LCount - 1];
    repeat
      TGcmUtilities.Square(LPowX2);
      FLookupPowX2.Add(LPowX2);
      System.Inc(LCount);
    until LCount > ABit;
  end;
end;

end.
