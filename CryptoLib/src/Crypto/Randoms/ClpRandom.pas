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

unit ClpRandom;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpIRandom;

resourcestring
  SBufferNil = 'Buffer Cannot be Nil';
  SMaxValueNegative = 'maxValue Must be Positive';
  SInvalidMinValue = 'minValue Cannot be Greater Than maxValue';

type
  TRandom = class(TInterfacedObject, IRandom)

  strict private
  const
    FMSEED = Int32(161803398);

  var
    FSeedArray: array [0 .. 55] of Int32;
    Finext, Finextp: Int32;

    function InternalSample(): Int32; inline;
    function GetSampleForLargeRange(): Double;

  strict protected
    /// <summary>Returns a random floating-point number between 0.0 and 1.0.</summary>
    /// <returns>A double-precision floating point number that is greater than or equal to 0.0, and less than 1.0.</returns>
    function Sample(): Double; virtual;

  public
    /// <summary>Initializes a new instance of the <see cref="T:System.Random" /> class, using a time-dependent default seed value.</summary>
    constructor Create(); overload;
    constructor Create(ASeed: Int32); overload;

    /// <summary>Returns a non-negative random integer.</summary>
    /// <returns>A 32-bit signed integer that is greater than or equal to 0 and less than <see cref="F:System.Int32.MaxValue" />.</returns>
    /// <filterpriority>1</filterpriority>
    function Next(): Int32; overload; virtual;

    /// <summary>Returns a non-negative random integer that is less than the specified maximum.</summary>
    /// <returns>A 32-bit signed integer that is greater than or equal to 0, and less than <paramref name="AMaxValue" />; that is, the range of return values ordinarily includes 0 but not <paramref name="AMaxValue" />. However, if <paramref name="AMaxValue" /> equals 0, <paramref name="AMaxValue" /> is returned.</returns>
    /// <param name="AMaxValue">The exclusive upper bound of the random number to be generated. <paramref name="AMaxValue" /> must be greater than or equal to 0. </param>
    /// <exception cref="EArgumentOutOfRangeCryptoLibException">
    /// <paramref name="AMaxValue" /> is less than 0. </exception>
    /// <filterpriority>1</filterpriority>
    function Next(AMaxValue: Int32): Int32; overload; virtual;

    /// <summary>Returns a random integer that is within a specified range.</summary>
    /// <returns>A 32-bit signed integer greater than or equal to <paramref name="AMinValue" /> and less than <paramref name="AMaxValue" />; that is, the range of return values includes <paramref name="AMinValue" /> but not <paramref name="AMaxValue" />. If <paramref name="AMinValue" /> equals <paramref name="AMaxValue" />, <paramref name="AMinValue" /> is returned.</returns>
    /// <param name="AMinValue">The inclusive lower bound of the random number returned. </param>
    /// <param name="AMaxValue">The exclusive upper bound of the random number returned. <paramref name="AMaxValue" /> must be greater than or equal to <paramref name="AMinValue" />. </param>
    /// <exception cref="EArgumentOutOfRangeCryptoLibException">
    /// <paramref name="AMinValue" /> is greater than <paramref name="AMaxValue" />. </exception>
    /// <filterpriority>1</filterpriority>
    function Next(AMinValue, AMaxValue: Int32): Int32; overload; virtual;

    /// <summary>Returns a random floating-point number that is greater than or equal to 0.0, and less than 1.0.</summary>
    /// <returns>A double-precision floating point number that is greater than or equal to 0.0, and less than 1.0.</returns>
    /// <filterpriority>1</filterpriority>
    function NextDouble(): Double; virtual;

    /// <summary>
    /// Fills the elements of a specified array of bytes with random numbers.
    /// </summary>
    /// <param name="ABuf">
    /// An array of bytes to contain random numbers.
    /// </param>
    /// <exception cref="EArgumentNilCryptoLibException">
    /// <paramref name="ABuf" /> is nil.
    /// </exception>
    /// <filterpriority>1</filterpriority>
    procedure NextBytes(const ABuf: TCryptoLibByteArray); overload; virtual;

  end;

implementation

{ TRandom }

constructor TRandom.Create;
begin
{$IFDEF FPC}
  Create(Int32(TThread.GetTickCount64));
{$ELSE}
  Create(Int32(TThread.GetTickCount));
{$ENDIF FPC}
end;

constructor TRandom.Create(ASeed: Int32);
var
  LNum1, LNum2, LIndex1, LIndex2: Int32;
begin
  LNum1 := FMSEED - Abs(ASeed);
  FSeedArray[55] := LNum1;
  LNum2 := 1;
  for LIndex1 := 1 to System.Pred(55) do
  begin
    LIndex2 := 21 * LIndex1 mod 55;
    FSeedArray[LIndex2] := LNum2;
    LNum2 := LNum1 - LNum2;
    if (LNum2 < 0) then
      LNum2 := LNum2 + System.High(Int32);
    LNum1 := FSeedArray[LIndex2];
  end;

  LIndex1 := 1;
  while LIndex1 < 5 do
  begin
    for LIndex2 := 1 to System.Pred(56) do
    begin
      FSeedArray[LIndex2] := FSeedArray[LIndex2] - FSeedArray
        [1 + (LIndex2 + 30) mod 55];
      if (FSeedArray[LIndex2] < 0) then
        FSeedArray[LIndex2] := FSeedArray[LIndex2] + System.High(Int32);
    end;
    System.Inc(LIndex1);
  end;

  Finext := 0;
  Finextp := 21;
end;

function TRandom.InternalSample: Int32;
var
  LInext, LInextp, LIndex1, LIndex2, LNum: Int32;
begin
  LInext := Finext;
  LInextp := Finextp;
  LIndex1 := LInext + 1;
  if ((LIndex1) >= 56) then
    LIndex1 := 1;

  LIndex2 := LInextp + 1;
  if ((LIndex2) >= 56) then
    LIndex2 := 1;
  LNum := FSeedArray[LIndex1] - FSeedArray[LIndex2];
  if (LNum < 0) then
    LNum := LNum + System.High(Int32);
  FSeedArray[LIndex1] := LNum;
  Finext := LIndex1;
  Finextp := LIndex2;
  Result := LNum;
end;

function TRandom.GetSampleForLargeRange: Double;
var
  LNum: Int32;
begin
  LNum := InternalSample();
  if (InternalSample() mod 2 = 0) then
    LNum := -LNum;
  Result := (LNum + 2147483646.0) / 4294967293.0;
end;

function TRandom.Next(AMinValue, AMaxValue: Int32): Int32;
var
  LNum: Int64;
begin
  if (AMinValue > AMaxValue) then
  begin
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SInvalidMinValue);
  end;
  LNum := Int64(AMaxValue) - Int64(AMinValue);
  if (LNum <= Int64(System.High(Int32))) then
  begin
    Result := Int32(Trunc(Sample()) * LNum) + AMinValue;
    Exit;
  end;
  Result := Int32(Int64(Trunc(GetSampleForLargeRange()) * LNum) +
    Int64(AMinValue));
end;

function TRandom.Next(AMaxValue: Int32): Int32;
begin
  if (AMaxValue < 0) then
  begin
    raise EArgumentOutOfRangeCryptoLibException.CreateRes(@SMaxValueNegative);
  end;
  Result := Int32(Trunc(Sample() * AMaxValue));
end;

function TRandom.Next: Int32;
begin
  Result := InternalSample();
end;

procedure TRandom.NextBytes(const ABuf: TCryptoLibByteArray);
var
  LI: Int32;
begin
  if (ABuf = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SBufferNil);

  for LI := System.Low(ABuf) to System.High(ABuf) do
  begin
    ABuf[LI] := Byte(InternalSample() mod (255 + 1));
  end;

end;

function TRandom.NextDouble: Double;
begin
  Result := Sample();
end;

function TRandom.Sample: Double;
begin
  Result := InternalSample() * 4.6566128752458E-10;
end;

end.
