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

unit ClpPbeParametersGenerator;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpICipherParameters,
  ClpIPbeParametersGenerator,
  ClpConverters,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// base class for all Password Based Encryption (Pbe) parameter generator
  /// classes.
  /// </summary>
  TPbeParametersGenerator = class abstract(TInterfacedObject,
    IPbeParametersGenerator)
  strict protected
  var
    FPassword, FSalt: TCryptoLibByteArray;
    FIterationCount: Int32;

  public

    procedure Clear(); virtual;

    destructor Destroy; override;

    /// <summary>
    /// Initialise the PBE generator.
    /// </summary>
    /// <param name="APassword">the password converted into bytes (see below).</param>
    /// <param name="ASalt">the salt to be mixed with the password.</param>
    /// <param name="AIterationCount">the number of iterations the "mixing"
    /// function is to be applied for.</param>
    procedure Init(const APassword, ASalt: TCryptoLibByteArray;
      AIterationCount: Int32); virtual;

    function GetPassword: TCryptoLibByteArray; virtual;
    function GetSalt: TCryptoLibByteArray; virtual;
    function GetIterationCount: Int32; virtual;

    property Password: TCryptoLibByteArray read GetPassword;
    property Salt: TCryptoLibByteArray read GetSalt;
    property IterationCount: Int32 read GetIterationCount;

    /// <summary>
    /// Generate derived parameters for a key of length keySize.
    /// </summary>
    /// <param name="AAlgorithm">
    /// a parameters object representing a key.
    /// </param>
    /// <param name="AKeySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key.
    /// </returns>
    function GenerateDerivedParameters(const AAlgorithm: String; AKeySize: Int32)
      : ICipherParameters; overload; virtual; abstract;

    /// <summary>
    /// Generate derived parameters for a key of length keySize and iv
    /// of length ivSize.
    /// </summary>
    /// <param name="AAlgorithm">
    /// a parameters object representing a key.
    /// </param>
    /// <param name="AKeySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <param name="AIvSize">
    /// the length, in bits, of the iv required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key and an iv.
    /// </returns>
    function GenerateDerivedParameters(const AAlgorithm: String;
      AKeySize, AIvSize: Int32): ICipherParameters; overload; virtual; abstract;

    /// <summary>
    /// Generate derived parameters for a key of length keySize,
    /// specifically <br />for use with a MAC.
    /// </summary>
    /// <param name="AKeySize">
    /// the length, in bits, of the key required.
    /// </param>
    /// <returns>
    /// a parameters object representing a key.
    /// </returns>
    function GenerateDerivedMacParameters(AKeySize: Int32): ICipherParameters;
      virtual; abstract;

    /// <summary>
    /// converts a password to a byte array according to the scheme in Pkcs5 (ascii, no padding)
    /// </summary>
    class function Pkcs5PasswordToBytes(const APassword: TCryptoLibCharArray)
      : TCryptoLibByteArray; static;

    /// <summary>
    /// converts a password to a byte array according to the scheme in PKCS5 (UTF-8, no padding)
    /// </summary>
    class function Pkcs5PasswordToUtf8Bytes(const APassword: TCryptoLibCharArray)
      : TCryptoLibByteArray; static;

    /// <summary>
    /// converts a password to a byte array according to the scheme in PKCS#12
    /// (unicode, big endian, 2 zero pad bytes at the end).
    /// </summary>
    class function Pkcs12PasswordToBytes(const APassword: TCryptoLibCharArray)
      : TCryptoLibByteArray; overload; static;
    /// <summary>
    /// converts a password to a byte array according to the scheme in PKCS#12
    /// (unicode, big endian, 2 zero pad bytes at the end).
    /// </summary>
    /// <param name="AWrongPkcs12Zero">if true, return 2 zero bytes when password is empty (wrong PKCS#12 variant).</param>
    class function Pkcs12PasswordToBytes(const APassword: TCryptoLibCharArray;
      AWrongPkcs12Zero: Boolean): TCryptoLibByteArray; overload; static;

  end;

implementation

destructor TPbeParametersGenerator.Destroy;
begin
  Clear();
  inherited Destroy;
end;

procedure TPbeParametersGenerator.Init(const APassword, ASalt: TCryptoLibByteArray;
  AIterationCount: Int32);
begin
 (* if APassword = nil then
    raise EArgumentNilCryptoLibException.Create('APassword');
  if ASalt = nil then
    raise EArgumentNilCryptoLibException.Create('ASalt');  *)

  FPassword := System.Copy(APassword);
  FSalt := System.Copy(ASalt);
  FIterationCount := AIterationCount;
end;

function TPbeParametersGenerator.GetPassword: TCryptoLibByteArray;
begin
  Result := System.Copy(FPassword);
end;

function TPbeParametersGenerator.GetSalt: TCryptoLibByteArray;
begin
  Result := System.Copy(FSalt);
end;

function TPbeParametersGenerator.GetIterationCount: Int32;
begin
  Result := FIterationCount;
end;

procedure TPbeParametersGenerator.Clear;
begin
  if FPassword <> nil then
  begin
    TArrayUtilities.Fill<Byte>(FPassword, 0, System.Length(FPassword), Byte(0));
    FPassword := nil;
  end;
  if FSalt <> nil then
  begin
    TArrayUtilities.Fill<Byte>(FSalt, 0, System.Length(FSalt), Byte(0));
    FSalt := nil;
  end;
  FIterationCount := 0;
end;

class function TPbeParametersGenerator.Pkcs5PasswordToBytes(
  const APassword: TCryptoLibCharArray): TCryptoLibByteArray;
var
  LStr: String;
begin
  Result := nil;
  if (APassword = nil) or (System.Length(APassword) < 1) then
    Exit;
  LStr := TConverters.ConvertCharArrayToString(APassword);
  Result := TConverters.ConvertStringToBytes(LStr, TEncoding.ANSI);
end;

class function TPbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(
  const APassword: TCryptoLibCharArray): TCryptoLibByteArray;
var
  LStr: String;
begin
  Result := nil;
  if (APassword = nil) or (System.Length(APassword) < 1) then
    Exit;
  LStr := TConverters.ConvertCharArrayToString(APassword);
  Result := TConverters.ConvertStringToBytes(LStr, TEncoding.UTF8);
end;

class function TPbeParametersGenerator.Pkcs12PasswordToBytes(
  const APassword: TCryptoLibCharArray): TCryptoLibByteArray;
begin
  Result := Pkcs12PasswordToBytes(APassword, False);
end;

class function TPbeParametersGenerator.Pkcs12PasswordToBytes(
  const APassword: TCryptoLibCharArray;
  AWrongPkcs12Zero: Boolean): TCryptoLibByteArray;
var
  LStr: String;
  LBytes: TCryptoLibByteArray;
  LNumBytes: Int32;
begin
  if (APassword = nil) or (System.Length(APassword) < 1) then
  begin
    if AWrongPkcs12Zero then
    begin
      System.SetLength(Result, 2);
      TArrayUtilities.Fill<Byte>(Result, 0, System.Length(Result), Byte(0));
    end
    else
      Result := nil;
    Exit;
  end;
  LStr := TConverters.ConvertCharArrayToString(APassword);
  LBytes := TConverters.ConvertStringToBytes(LStr, TEncoding.BigEndianUnicode);
  LNumBytes := System.Length(LBytes);
  System.SetLength(Result, LNumBytes + 2);
  if LNumBytes > 0 then
    System.Move(LBytes[0], Result[0], LNumBytes * System.SizeOf(Byte));
  Result[LNumBytes] := 0;
  Result[LNumBytes + 1] := 0;
end;

end.
