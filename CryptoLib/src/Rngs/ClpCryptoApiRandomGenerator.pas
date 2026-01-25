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

unit ClpCryptoApiRandomGenerator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIRandomNumberGenerator,
  ClpRandomNumberGenerator,
  ClpICryptoApiRandomGenerator,
  ClpIRandomGenerator,
  ClpCryptoLibTypes;

resourcestring
  SNegativeOffset = 'Start Offset Cannot be Negative, "Start"';
  SArrayTooSmall = 'Byte Array Too Small For Requested Offset and Length';

type
  /// <summary>
  /// Uses TRandomNumberGenerator.CreateRng() to Get randomness generator
  /// </summary>
  TCryptoApiRandomGenerator = class(TInterfacedObject, ICryptoApiRandomGenerator, IRandomGenerator)

  strict private
  var
    FrndProv: IRandomNumberGenerator;

  public
    /// <summary>
    /// Uses TRandomNumberGenerator.Create() to Get randomness generator
    /// </summary>
    constructor Create(); overload;
    constructor Create(const ARng: IRandomNumberGenerator); overload;

    /// <summary>Add more seed material to the generator.</summary>
    /// <param name="ASeed">A byte array to be mixed into the generator's state.</param>
    procedure AddSeedMaterial(const ASeed: TCryptoLibByteArray);
      overload; virtual;

    /// <summary>Add more seed material to the generator.</summary>
    /// <param name="ASeed">A long value to be mixed into the generator's state.</param>
    procedure AddSeedMaterial(ASeed: Int64); overload; virtual;

    /// <summary>Fill byte array with random values.</summary>
    /// <param name="ABytes">Array to be filled.</param>
    procedure NextBytes(const ABytes: TCryptoLibByteArray); overload; virtual;

    /// <summary>Fill byte array with random values.</summary>
    /// <param name="ABytes">Array to receive bytes.</param>
    /// <param name="AStart">Index to start filling at.</param>
    /// <param name="ALen">Length of segment to fill.</param>
    procedure NextBytes(const ABytes: TCryptoLibByteArray; AStart, ALen: Int32);
      overload; virtual;

  end;

implementation

{ TCryptoApiRandomGenerator }

procedure TCryptoApiRandomGenerator.AddSeedMaterial(ASeed: Int64);
begin
  // We don't care about the seed
end;

procedure TCryptoApiRandomGenerator.AddSeedMaterial
  (const ASeed: TCryptoLibByteArray);
begin
  // We don't care about the seed
end;

constructor TCryptoApiRandomGenerator.Create(const ARng: IRandomNumberGenerator);
begin
  inherited Create();
  FRndProv := ARng;
end;

constructor TCryptoApiRandomGenerator.Create;
begin
  Create(TRandomNumberGenerator.CreateRng());
end;

procedure TCryptoApiRandomGenerator.NextBytes(const ABytes: TCryptoLibByteArray);
begin
  FRndProv.GetBytes(ABytes);
end;

procedure TCryptoApiRandomGenerator.NextBytes(const ABytes: TCryptoLibByteArray;
  AStart, ALen: Int32);
var
  LTmpBuf: TCryptoLibByteArray;
begin
  if (AStart < 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SNegativeOffset);
  end;
  if (System.Length(ABytes) < (AStart + ALen)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SArrayTooSmall);

  end;

  if ((System.Length(ABytes) = ALen) and (AStart = 0)) then
  begin
    NextBytes(ABytes);
  end
  else
  begin
    System.SetLength(LTmpBuf, ALen);
    NextBytes(LTmpBuf);

    System.Move(LTmpBuf[0], ABytes[AStart], ALen * System.SizeOf(Byte));

  end;
end;

end.
