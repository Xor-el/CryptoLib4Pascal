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

unit ClpCryptoLibTypes;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils;

type
  // Plain procedure pointer overloads
  TCryptoLibProc = procedure;
  TCryptoLibProc<T1> = procedure(Arg1: T1);
  TCryptoLibProc<T1, T2> = procedure(Arg1: T1; Arg2: T2);
  TCryptoLibProc<T1, T2, T3> = procedure(Arg1: T1; Arg2: T2; Arg3: T3);
  TCryptoLibProc<T1, T2, T3, T4> = procedure(Arg1: T1; Arg2: T2; Arg3: T3; Arg4: T4);

  // Plain function pointer overloads
  TCryptoLibFunc<TResult> = function: TResult;
  TCryptoLibFunc<T1, TResult> = function(Arg1: T1): TResult;
  TCryptoLibFunc<T1, T2, TResult> = function(Arg1: T1; Arg2: T2): TResult;
  TCryptoLibFunc<T1, T2, T3, TResult> = function(Arg1: T1; Arg2: T2; Arg3: T3): TResult;
  TCryptoLibFunc<T1, T2, T3, T4, TResult> = function(Arg1: T1; Arg2: T2; Arg3: T3; Arg4: T4): TResult;

  TCryptoLibPredicate<T> = function(Arg1: T): Boolean;

  // Method-of-object procedure overloads
  TCryptoLibMethodProc = procedure of object;
  TCryptoLibMethodProc<T1> = procedure(Arg1: T1) of object;
  TCryptoLibMethodProc<T1, T2> = procedure(Arg1: T1; Arg2: T2) of object;
  TCryptoLibMethodProc<T1, T2, T3> = procedure(Arg1: T1; Arg2: T2; Arg3: T3) of object;
  TCryptoLibMethodProc<T1, T2, T3, T4> = procedure(Arg1: T1; Arg2: T2; Arg3: T3; Arg4: T4) of object;

  // Method-of-object function overloads
  TCryptoLibMethodFunc<TResult> = function: TResult of object;
  TCryptoLibMethodFunc<T1, TResult> = function(Arg1: T1): TResult of object;
  TCryptoLibMethodFunc<T1, T2, TResult> = function(Arg1: T1; Arg2: T2): TResult of object;
  TCryptoLibMethodFunc<T1, T2, T3, TResult> = function(Arg1: T1; Arg2: T2; Arg3: T3): TResult of object;
  TCryptoLibMethodFunc<T1, T2, T3, T4, TResult> = function(Arg1: T1; Arg2: T2; Arg3: T3; Arg4: T4): TResult of object;

  TCryptoLibMethodPredicate<T> = function(Arg1: T): Boolean of object;

  ECryptoLibException = class(Exception);
  EInvalidCastCryptoLibException = class(EInvalidCast);
  EArithmeticCryptoLibException = class(ECryptoLibException);
  EInvalidOperationCryptoLibException = class(ECryptoLibException);
  EInvalidParameterCryptoLibException = class(ECryptoLibException);
  EIndexOutOfRangeCryptoLibException = class(ECryptoLibException);
  EArgumentCryptoLibException = class(ECryptoLibException);
  EInvalidArgumentCryptoLibException = class(ECryptoLibException);
  EArgumentNilCryptoLibException = class(ECryptoLibException);
  EArgumentOutOfRangeCryptoLibException = class(ECryptoLibException);
  ENullReferenceCryptoLibException = class(ECryptoLibException);
  EUnsupportedTypeCryptoLibException = class(ECryptoLibException);
  EIOCryptoLibException = class(ECryptoLibException);
  EFormatCryptoLibException = class(ECryptoLibException);
  ENotImplementedCryptoLibException = class(ECryptoLibException);
  ENotSupportedCryptoLibException = class(ECryptoLibException);
  EEndOfStreamCryptoLibException = class(EIOCryptoLibException);
  EStreamOverflowCryptoLibException = class(ECryptoLibException);
  EAsn1CryptoLibException = class(EIOCryptoLibException);
  EAsn1ParsingCryptoLibException = class(ECryptoLibException);
  EInvalidKeyCryptoLibException = class(ECryptoLibException);
  EInvalidCipherTextCryptoLibException = class(ECryptoLibException);
  EStreamCryptoLibException = class(ECryptoLibException);
  ESecurityUtilityCryptoLibException = class(ECryptoLibException);
  EOSRandomCryptoLibException = class(ECryptoLibException);
  EDataLengthCryptoLibException = class(ECryptoLibException);
  EMaxBytesExceededCryptoLibException = class(ECryptoLibException);
  EOutputLengthCryptoLibException = class(EDataLengthCryptoLibException);
  EBadBlockCryptoLibException = class(ECryptoLibException);
  EPemCryptoLibException = class(EIOCryptoLibException);
  EPemGenerationCryptoLibException = class(ECryptoLibException);
  ECertificateCryptoLibException = class(ECryptoLibException);
  ECrlCryptoLibException = class(ECryptoLibException);
  EPkcsCryptoLibException = class(ECryptoLibException);
  EPkcsIOCryptoLibException = class(EIOCryptoLibException);
  EPkixCertPathBuilderCryptoLibException = class(ECryptoLibException);
  EOcspCryptoLibException = class(ECryptoLibException);

  /// <summary>
  /// Raised when certification path validation fails.
  /// </summary>
  /// <remarks>
  /// <see cref="Index" /> is the position in the path of the certificate that failed, counted from
  /// the end entity, and is -1 when no single certificate is to blame or the raise site does not
  /// know its position. It is deliberately not defaulted to 0, which is a real position.
  /// </remarks>
  EPkixCertPathValidatorCryptoLibException = class(ECryptoLibException)

  strict private
  var
    FIndex: Int32;
    FHasIndex: Boolean;

    function GetIndex: Int32;

  public
    /// <summary>
    /// Re-raises an already-formed message against a position in the path. For a raise site that
    /// knows the position wrapping one that did not, so the message survives unaltered.
    /// </summary>
    constructor CreateAt(AIndex: Int32; const AMsg: String);
    /// <summary>As CreateRes, but records the position in the path that failed.</summary>
    constructor CreateResAt(AIndex: Int32; AResStringRec: PResStringRec);
    /// <summary>As CreateResFmt, but records the position in the path that failed.</summary>
    constructor CreateResFmtAt(AIndex: Int32; AResStringRec: PResStringRec;
      const AArgs: array of const);

    property Index: Int32 read GetIndex;
  end;
  /// <summary>
  /// Raised when a revocation mechanism could not settle the status of a certificate, so a peer
  /// mechanism may still answer for it. It is not by itself a path validation failure.
  /// </summary>
  ERecoverablePkixCertPathValidatorCryptoLibException = class(EPkixCertPathValidatorCryptoLibException);

  EPkixNameConstraintValidatorCryptoLibException = class(ECryptoLibException);

  /// <summary>
  /// Represents a dynamic array of Byte.
  /// </summary>
  TCryptoLibByteArray = TBytes;

  /// <summary>
  /// Represents a dynamic generic array of Type T.
  /// </summary>
  TCryptoLibGenericArray<T> = array of T;

  /// <summary>
  /// Represents a dynamic generic array of array of Type T.
  /// </summary>
  TCryptoLibMatrixGenericArray<T> = array of TCryptoLibGenericArray<T>;

  /// <summary>
  /// Represents a dynamic array of Boolean.
  /// </summary>
  TCryptoLibBooleanArray = TCryptoLibGenericArray<Boolean>;

  /// <summary>
  /// Represents a dynamic array of ShortInt.
  /// </summary>
  TCryptoLibShortIntArray = TCryptoLibGenericArray<ShortInt>;

  /// <summary>
  /// Represents a dynamic array of SmallInt.
  /// </summary>
  TCryptoLibSmallIntArray = TCryptoLibGenericArray<SmallInt>;

  /// <summary>
  /// Represents a dynamic array of Int32.
  /// </summary>
  TCryptoLibInt32Array = TCryptoLibGenericArray<Int32>;

  /// <summary>
  /// Represents a dynamic array of Int64.
  /// </summary>
  TCryptoLibInt64Array = TCryptoLibGenericArray<Int64>;

  /// <summary>
  /// Represents a dynamic array of UInt16.
  /// </summary>
  TCryptoLibUInt16Array = TCryptoLibGenericArray<UInt16>;

  /// <summary>
  /// Represents a dynamic array of UInt32.
  /// </summary>
  TCryptoLibUInt32Array = TCryptoLibGenericArray<UInt32>;

  /// <summary>
  /// Represents a dynamic array of UInt64.
  /// </summary>
  TCryptoLibUInt64Array = TCryptoLibGenericArray<UInt64>;

  /// <summary>
  /// Represents a dynamic array of String.
  /// </summary>
  TCryptoLibStringArray = TCryptoLibGenericArray<String>;

  /// <summary>
  /// Represents a dynamic array of Char.
  /// </summary>
  TCryptoLibCharArray = TCryptoLibGenericArray<Char>;

  /// <summary>
  /// Represents a dynamic array of array of ShortInt.
  /// </summary>
  TCryptoLibMatrixShortIntArray = TCryptoLibGenericArray<TCryptoLibShortIntArray>;

  /// <summary>
  /// Represents a dynamic array of array of byte.
  /// </summary>
  TCryptoLibMatrixByteArray = TCryptoLibGenericArray<TCryptoLibByteArray>;

  /// <summary>
  /// Represents a dynamic array of array of Int32.
  /// </summary>
  TCryptoLibMatrixInt32Array = TCryptoLibGenericArray<TCryptoLibInt32Array>;

  /// <summary>
  /// Represents a dynamic array of array of UInt32.
  /// </summary>
  TCryptoLibMatrixUInt32Array = TCryptoLibGenericArray<TCryptoLibUInt32Array>;

  /// <summary>
  /// Represents a dynamic array of array of UInt64.
  /// </summary>
  TCryptoLibMatrixUInt64Array = TCryptoLibGenericArray<TCryptoLibUInt64Array>;

implementation

{ EPkixCertPathValidatorCryptoLibException }

constructor EPkixCertPathValidatorCryptoLibException.CreateAt(AIndex: Int32; const AMsg: String);
begin
  inherited Create(AMsg);
  FIndex := AIndex;
  FHasIndex := True;
end;

constructor EPkixCertPathValidatorCryptoLibException.CreateResAt(AIndex: Int32;
  AResStringRec: PResStringRec);
begin
  inherited CreateRes(AResStringRec);
  FIndex := AIndex;
  FHasIndex := True;
end;

constructor EPkixCertPathValidatorCryptoLibException.CreateResFmtAt(AIndex: Int32;
  AResStringRec: PResStringRec; const AArgs: array of const);
begin
  inherited CreateResFmt(AResStringRec, AArgs);
  FIndex := AIndex;
  FHasIndex := True;
end;

function EPkixCertPathValidatorCryptoLibException.GetIndex: Int32;
begin
  // the inherited constructors leave the fields zeroed, and 0 is a real position
  if FHasIndex then
    Result := FIndex
  else
    Result := -1;
end;

{$IFDEF FPC}

initialization

// Set UTF-8 in AnsiStrings, just like Lazarus
SetMultiByteConversionCodePage(CP_UTF8);
// SetMultiByteFileSystemCodePage(CP_UTF8); not needed, this is the default under Windows
SetMultiByteRTLFileSystemCodePage(CP_UTF8);
{$ENDIF FPC}

end.
