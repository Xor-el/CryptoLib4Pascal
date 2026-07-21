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
  SysUtils;

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

{ EBip327InvalidContributionCryptoLibException }

constructor EBip327InvalidContributionCryptoLibException.Create(const AMessage: string;
  ASignerIndex: Int32; const AContribution: string);
begin
  inherited Create(AMessage);
  FSignerIndex := ASignerIndex;
  FContribution := AContribution;
end;

end.
