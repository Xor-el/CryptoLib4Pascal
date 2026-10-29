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

unit ClpCryptoLibExceptions;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpPkixCertPathValidatorReason;

type
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
  EOcspCryptoLibException = class(ECryptoLibException);

  /// <summary>
  /// Raised when no certification path can be built. <see cref="Reason" /> gives the most specific
  /// cause among the candidate paths tried, Unspecified when none was set.
  /// </summary>
  EPkixCertPathBuilderCryptoLibException = class(ECryptoLibException)

  strict private
  var
    FReason: TPkixCertPathValidatorReason;

  public
    /// <summary>As Create, but records a reason.</summary>
    constructor CreateReason(AReason: TPkixCertPathValidatorReason; const AMsg: String);
    /// <summary>As CreateRes, but records a reason.</summary>
    constructor CreateResReason(AReason: TPkixCertPathValidatorReason; AResStringRec: PResStringRec);
    /// <summary>As CreateResFmt, but records a reason.</summary>
    constructor CreateResFmtReason(AReason: TPkixCertPathValidatorReason;
      AResStringRec: PResStringRec; const AArgs: array of const);

    property Reason: TPkixCertPathValidatorReason read FReason;
  end;

  /// <summary>
  /// Raised when certification path validation fails.
  /// </summary>
  /// <remarks>
  /// <see cref="Index" /> is the position in the path of the certificate that failed, counted from
  /// the end entity, and is -1 when no single certificate is to blame or the raise site does not
  /// know its position. It is deliberately not defaulted to 0, which is a real position.
  /// <see cref="Reason" /> gives the machine-readable cause, Unspecified when none was set.
  /// </remarks>
  EPkixCertPathValidatorCryptoLibException = class(ECryptoLibException)

  strict private
  var
    FIndex: Int32;
    FHasIndex: Boolean;
    FReason: TPkixCertPathValidatorReason;

    function GetIndex: Int32;
    function GetReason: TPkixCertPathValidatorReason;

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
    /// <summary>As CreateAt, but records a reason instead of only a position. A position of
    /// AIndex &lt; 0 means none, so a raise site re-wrapping another can preserve its reason.</summary>
    constructor CreateReason(AReason: TPkixCertPathValidatorReason; AIndex: Int32;
      const AMsg: String);
    /// <summary>As CreateResAt, but records a reason (AIndex &lt; 0 means no position).</summary>
    constructor CreateResReason(AReason: TPkixCertPathValidatorReason; AIndex: Int32;
      AResStringRec: PResStringRec);
    /// <summary>As CreateResFmtAt, but records a reason (AIndex &lt; 0 means no position).</summary>
    constructor CreateResFmtReason(AReason: TPkixCertPathValidatorReason; AIndex: Int32;
      AResStringRec: PResStringRec; const AArgs: array of const);

    property Index: Int32 read GetIndex;
    property Reason: TPkixCertPathValidatorReason read GetReason;
  end;
  /// <summary>
  /// Raised when a revocation mechanism could not settle the status of a certificate, so a peer
  /// mechanism may still answer for it. It is not by itself a path validation failure.
  /// </summary>
  ERecoverablePkixCertPathValidatorCryptoLibException = class(EPkixCertPathValidatorCryptoLibException);

  EPkixNameConstraintValidatorCryptoLibException = class(ECryptoLibException);

  /// <summary>
  /// Raised when a signer or the nonce aggregator sends an invalid contribution.
  /// FSignerIndex is the 0-based signer index, or -1 for aggregator (e.g. invalid aggnonce).
  /// FContribution is one of 'pubkey', 'pubnonce', 'aggnonce', 'psig'.
  /// </summary>
  EBip327InvalidContributionCryptoLibException = class(ECryptoLibException)
  strict private
    var
      FSignerIndex: Int32;
      FContribution: string;
  public
    constructor Create(const AMessage: string; ASignerIndex: Int32;
      const AContribution: string);
    property SignerIndex: Int32 read FSignerIndex;
    property Contribution: string read FContribution;
  end;

implementation

{ EPkixCertPathBuilderCryptoLibException }

constructor EPkixCertPathBuilderCryptoLibException.CreateReason(
  AReason: TPkixCertPathValidatorReason; const AMsg: String);
begin
  inherited Create(AMsg);
  FReason := AReason;
end;

constructor EPkixCertPathBuilderCryptoLibException.CreateResReason(
  AReason: TPkixCertPathValidatorReason; AResStringRec: PResStringRec);
begin
  inherited CreateRes(AResStringRec);
  FReason := AReason;
end;

constructor EPkixCertPathBuilderCryptoLibException.CreateResFmtReason(
  AReason: TPkixCertPathValidatorReason; AResStringRec: PResStringRec;
  const AArgs: array of const);
begin
  inherited CreateResFmt(AResStringRec, AArgs);
  FReason := AReason;
end;

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

constructor EPkixCertPathValidatorCryptoLibException.CreateReason(
  AReason: TPkixCertPathValidatorReason; AIndex: Int32; const AMsg: String);
begin
  inherited Create(AMsg);
  FReason := AReason;
  FIndex := AIndex;
  FHasIndex := AIndex >= 0;
end;

constructor EPkixCertPathValidatorCryptoLibException.CreateResReason(
  AReason: TPkixCertPathValidatorReason; AIndex: Int32; AResStringRec: PResStringRec);
begin
  inherited CreateRes(AResStringRec);
  FReason := AReason;
  FIndex := AIndex;
  FHasIndex := AIndex >= 0;
end;

constructor EPkixCertPathValidatorCryptoLibException.CreateResFmtReason(
  AReason: TPkixCertPathValidatorReason; AIndex: Int32; AResStringRec: PResStringRec;
  const AArgs: array of const);
begin
  inherited CreateResFmt(AResStringRec, AArgs);
  FReason := AReason;
  FIndex := AIndex;
  FHasIndex := AIndex >= 0;
end;

function EPkixCertPathValidatorCryptoLibException.GetReason: TPkixCertPathValidatorReason;
begin
  Result := FReason;
end;

function EPkixCertPathValidatorCryptoLibException.GetIndex: Int32;
begin
  // the inherited constructors leave the fields zeroed, and 0 is a real position
  if FHasIndex then
    Result := FIndex
  else
    Result := -1;
end;

{ EBip327InvalidContributionCryptoLibException }

constructor EBip327InvalidContributionCryptoLibException.Create(const AMessage: string;
  ASignerIndex: Int32; const AContribution: string);
begin
  inherited Create(AMessage);
  FSignerIndex := ASignerIndex;
  FContribution := AContribution;
end;

end.
