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

unit ClpFixedSecureRandom;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
  ClpEncoders,
  ClpCryptoLibTypes,
  ClpConverters,
  ClpBigInteger,
  ClpIFixedSecureRandom,
  ClpISecureRandom,
  ClpSecureRandom;

resourcestring
  SErrorSavingArray = 'can''t save value array.';
  SErrorSavingSource = 'can''t save value source.';
  SUnRecognizedImplementation = 'Unrecognized BigIntegerSource Implementation';

type
  TFixedSecureRandom = class(TSecureRandom, IFixedSecureRandom)

  strict private
  var
    F_data: TCryptoLibByteArray;
    F_index: Int32;

  class var

    FREGULAR, FANDROID, FCLASSPATH: TBigInteger;

    FisAndroidStyle, FisClasspathStyle, FisRegularStyle: Boolean;

    class procedure Boot(); static;
    class constructor FixedSecureRandom();

  type
    TRandomChecker = class(TSecureRandom, IRandomChecker)

    public
    var
      Fdata: TCryptoLibByteArray;
      Findex: Int32;
      constructor Create();

      procedure NextBytes(const bytes: TCryptoLibByteArray); override;

    end;

  class function ExpandToBitLength(bitLength: Int32;
    const v: TCryptoLibByteArray): TCryptoLibByteArray; static;

  strict protected
    function GetIsExhausted: Boolean; inline;
    constructor Create(const data: TCryptoLibByteArray); overload;

  public

    type

    /// <summary>
    /// Base class for sources of fixed "Randomness"
    /// </summary>
    TSource = class(TInterfacedObject, ISource)

    strict private
    var
      Fdata: TCryptoLibByteArray;
    strict protected
      function GetData: TCryptoLibByteArray; inline;

    public
      property data: TCryptoLibByteArray read GetData;
      constructor Create(const data: TCryptoLibByteArray);

    end;

  type

    /// <summary>
    /// Data Source - in this case we just expect requests for byte arrays.
    /// </summary>
    TData = class(TSource, IData)

    public

      constructor Create(const data: TCryptoLibByteArray);

    end;

  type

    /// <summary>
    /// BigInteger Source - in this case we expect requests for data that
    /// will be used <br />for BigIntegers. The FixedSecureRandom will
    /// attempt to compensate for platform differences here.
    /// </summary>
    TBigIntegerSource = class(TSource, IBigIntegerSource)

    public

      constructor Create(const data: TCryptoLibByteArray); overload;
      constructor Create(bitLength: Int32;
        const data: TCryptoLibByteArray); overload;
      constructor Create(const hexData: String); overload;
      constructor Create(bitLength: Int32; const hexData: String); overload;

    end;

  function GenerateSeed(numBytes: Int32): TCryptoLibByteArray; override;

  procedure NextBytes(const buf: TCryptoLibByteArray); overload; override;
  procedure NextBytes(const buf: TCryptoLibByteArray; off, len: Int32);
    overload; override;

  property IsExhausted: Boolean read GetIsExhausted;

  constructor Create(const sources: TCryptoLibGenericArray<ISource>); overload;

  class function From(const values: TCryptoLibMatrixByteArray)
    : IFixedSecureRandom; static;

  end;

implementation

{ TFixedSecureRandom }

constructor TFixedSecureRandom.Create(const data: TCryptoLibByteArray);
begin
  Inherited Create();
  F_data := data;
end;

class procedure TFixedSecureRandom.Boot;
var
  Fcheck1, Fcheck2: TBigInteger;
begin
  FREGULAR := TBigInteger.Create('01020304ffffffff0506070811111111', 16);
  FANDROID := TBigInteger.Create('1111111105060708ffffffff01020304', 16);
  FCLASSPATH := TBigInteger.Create('3020104ffffffff05060708111111', 16);

  Fcheck1 := TBigInteger.Create(128, TRandomChecker.Create() as ISecureRandom);
  Fcheck2 := TBigInteger.Create(120, TRandomChecker.Create() as ISecureRandom);

  FisAndroidStyle := Fcheck1.Equals(FANDROID);
  FisRegularStyle := Fcheck1.Equals(FREGULAR);
  FisClasspathStyle := Fcheck2.Equals(FCLASSPATH);
end;

constructor TFixedSecureRandom.Create(const sources
  : TCryptoLibGenericArray<ISource>);
var
  bOut: TMemoryStream;
  data: TCryptoLibByteArray;
  i, len, w: Int32;
begin
  Inherited Create();
  bOut := TMemoryStream.Create();
  try
    if (FisRegularStyle) then
    begin
      if (FisClasspathStyle) then

      begin

        i := 0;
        while i <> System.Length(sources) do

        begin
          try

            if (Supports(sources[i], IBigIntegerSource)) then
            begin
              data := sources[i].data;
              len := System.Length(data) - (System.Length(data) mod 4);
              w := System.Length(data) - len - 1;
              while w >= 0 do

              begin
                bOut.Write(TCryptoLibByteArray.Create(data[w]), 1);
                System.Dec(w);
              end;
              w := System.Length(data) - len;
              while w < System.Length(data) do
              begin
                bOut.Write(data[w], 4);
                System.Inc(w, 4);
              end;
            end
            else
            begin
              bOut.Write(sources[i].data[0], System.Length(sources[i].data));
            end;

          except
            on e: EIOCryptoLibException do
            begin
              raise EArgumentCryptoLibException.CreateRes(@SErrorSavingSource);
            end;
          end;
          System.Inc(i);
        end
      end
      else
      begin
        i := 0;
        while i <> System.Length(sources) do
        begin
          try

            bOut.Write(sources[i].data[0], System.Length(sources[i].data));
          except
            on e: EIOCryptoLibException do
            begin
              raise EArgumentCryptoLibException.CreateRes(@SErrorSavingSource);
            end;
          end;
          System.Inc(i);
        end
      end
    end
    else if (FisAndroidStyle) then
    begin
      i := 0;
      while i <> System.Length(sources) do
      begin
        try

          if (Supports(sources[i], IBigIntegerSource)) then
          begin
            data := sources[i].data;
            len := System.Length(data) - (System.Length(data) mod 4);
            w := 0;
            while w < len do

            begin
              bOut.Write(data[System.Length(data) - (w + 4)], 4);
              System.Inc(w, 4);
            end;
            if ((System.Length(data) - len) <> 0) then
            begin

              w := 0;
              while (w <> (4 - (System.Length(data) - len))) do

              begin
                bOut.Write(TCryptoLibByteArray.Create(0), 1);
                System.Inc(w);
              end;
            end;
            w := 0;
            while (w <> (System.Length(data) - len)) do
            begin

              bOut.Write(TCryptoLibByteArray.Create(data[len + w]), 1);
              System.Inc(w);
            end
          end
          else
          begin
            bOut.Write(sources[i].data[0], System.Length(sources[i].data));
          end;

        except
          on e: EIOCryptoLibException do
          begin
            raise EArgumentCryptoLibException.CreateRes(@SErrorSavingSource);
          end;
        end;
        System.Inc(i);
      end;

    end
    else
    begin
      raise EInvalidOperationCryptoLibException.CreateRes
        (@SUnRecognizedImplementation);
    end;

    System.SetLength(F_data, bOut.Size);
    bOut.Position := 0;
    bOut.Read(F_data[0], bOut.Size);

  finally
    bOut.Free;

  end;

end;

class function TFixedSecureRandom.ExpandToBitLength(bitLength: Int32;
  const v: TCryptoLibByteArray): TCryptoLibByteArray;
var
  tmp, lv: TCryptoLibByteArray;
  i: UInt32;
begin
  lv := v;
  if (((bitLength + 7) div 8) > System.Length(lv)) then
  begin
    System.SetLength(tmp, (bitLength + 7) div 8);

    System.Move(lv[0], tmp[System.Length(tmp) - System.Length(lv)],
      System.Length(lv));

    if (FisAndroidStyle) then
    begin
      if (bitLength mod 8 <> 0) then
      begin
        i := TConverters.ReadBytesAsUInt32BE(PByte(tmp), 0);
        tmp := TConverters.ReadUInt32AsBytesBE(i shl (8 - (bitLength mod 8)));

      end;
    end;

    result := tmp;
    Exit;
  end
  else
  begin
    if (FisAndroidStyle and (bitLength < (System.Length(lv) * 8))) then
    begin
      if (bitLength mod 8 <> 0) then
      begin
        i := TConverters.ReadBytesAsUInt32BE(PByte(lv), 0);
        lv := TConverters.ReadUInt32AsBytesBE(i shl (8 - (bitLength mod 8)));

      end;
    end;
  end;

  result := lv;
end;

class constructor TFixedSecureRandom.FixedSecureRandom;
begin
  TFixedSecureRandom.Boot;
end;

class function TFixedSecureRandom.From(const values: TCryptoLibMatrixByteArray)
  : IFixedSecureRandom;
var
  bOut: TMemoryStream;
  i: Int32;
  v, temp: TCryptoLibByteArray;
begin
  bOut := TMemoryStream.Create();
  try

    i := 0;
    while i <> System.Length(values) do
    begin
      try

        v := values[i];
        bOut.Write(v[0], System.Length(v));

      except
        on e: EIOCryptoLibException do
        begin
          raise EArgumentCryptoLibException.CreateRes(@SErrorSavingArray);
        end;

      end;

      System.Inc(i);
    end;

    System.SetLength(temp, bOut.Size);
    bOut.Position := 0;
    bOut.Read(temp[0], bOut.Size);
    result := TFixedSecureRandom.Create(temp);
  finally
    bOut.Free;
  end;
end;

function TFixedSecureRandom.GenerateSeed(numBytes: Int32): TCryptoLibByteArray;
begin
  result := TSecureRandom.GetNextBytes(Self as ISecureRandom, numBytes);
end;

function TFixedSecureRandom.GetIsExhausted: Boolean;
begin
  result := F_index = System.Length(F_data);
end;

procedure TFixedSecureRandom.NextBytes(const buf: TCryptoLibByteArray);
begin
  System.Move(F_data[F_index], buf[0], System.Length(buf) *
    System.SizeOf(Byte));

  F_index := F_index + System.Length(buf);
end;

procedure TFixedSecureRandom.NextBytes(const buf: TCryptoLibByteArray;
  off, len: Int32);
begin
  System.Move(F_data[F_index], buf[off], len * System.SizeOf(Byte));

  F_index := F_index + len;
end;

{ TRandomChecker.TFixedSecureRandom }

constructor TFixedSecureRandom.TRandomChecker.Create;
begin
  Inherited Create();
  Fdata := THex.Decode('01020304ffffffff0506070811111111');
  Findex := 0;
end;

procedure TFixedSecureRandom.TRandomChecker.NextBytes
  (const bytes: TCryptoLibByteArray);
begin

  System.Move(Fdata[Findex], bytes[0], System.Length(bytes) *
    System.SizeOf(Byte));

  Findex := Findex + System.Length(bytes);

end;

{ TFixedSecureRandom.TSource }

constructor TFixedSecureRandom.TSource.Create(const data: TCryptoLibByteArray);
begin
  Inherited Create();
  Fdata := data;
end;

function TFixedSecureRandom.TSource.GetData: TCryptoLibByteArray;
begin
  result := Fdata;
end;

{ TFixedSecureRandom.TData }

constructor TFixedSecureRandom.TData.Create(const data: TCryptoLibByteArray);
begin
  Inherited Create(data);
end;

{ TFixedSecureRandom.TBigIntegerSource }

constructor TFixedSecureRandom.TBigIntegerSource.Create(bitLength: Int32;
  const data: TCryptoLibByteArray);
begin
  Inherited Create(ExpandToBitLength(bitLength, data));
end;

constructor TFixedSecureRandom.TBigIntegerSource.Create
  (const data: TCryptoLibByteArray);
begin
  Inherited Create(data);
end;

constructor TFixedSecureRandom.TBigIntegerSource.Create(bitLength: Int32;
  const hexData: String);
begin
  Inherited Create(ExpandToBitLength(bitLength, THex.Decode(hexData)));
end;

constructor TFixedSecureRandom.TBigIntegerSource.Create(const hexData: String);
begin
  Create(THex.Decode(hexData));
end;

end.
