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

unit ClpPkixCertRevocationCheckerParameters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIX509Certificate,
  ClpIAsymmetricKeyParameter,
  ClpIPkixTypes;

type
  /// <summary>
  /// The context handed to a revocation checker for one certificate of the path being validated
  /// (RFC 5280 6.1.3 (a)(3)).
  /// </summary>
  TPkixCertRevocationCheckerParameters = class sealed(TInterfacedObject,
    IPkixCertRevocationCheckerParameters)

  strict private
  var
    FPkixParameters: IPkixParameters;
    FValidDate: TDateTime;
    FCertPath: IPkixCertPath;
    FIndex: Int32;
    FSigningCert: IX509Certificate;
    FWorkingPublicKey: IAsymmetricKeyParameter;

    function GetPkixParameters: IPkixParameters;
    function GetValidDate: TDateTime;
    function GetCertPath: IPkixCertPath;
    function GetIndex: Int32;
    function GetSigningCert: IX509Certificate;
    function GetWorkingPublicKey: IAsymmetricKeyParameter;

  public
    constructor Create(const APkixParameters: IPkixParameters; AValidDate: TDateTime;
      const ACertPath: IPkixCertPath; AIndex: Int32; const ASigningCert: IX509Certificate;
      const AWorkingPublicKey: IAsymmetricKeyParameter);

    property PkixParameters: IPkixParameters read GetPkixParameters;
    property ValidDate: TDateTime read GetValidDate;
    property CertPath: IPkixCertPath read GetCertPath;
    property Index: Int32 read GetIndex;
    property SigningCert: IX509Certificate read GetSigningCert;
    property WorkingPublicKey: IAsymmetricKeyParameter read GetWorkingPublicKey;
  end;

implementation

{ TPkixCertRevocationCheckerParameters }

constructor TPkixCertRevocationCheckerParameters.Create(const APkixParameters: IPkixParameters;
  AValidDate: TDateTime; const ACertPath: IPkixCertPath; AIndex: Int32;
  const ASigningCert: IX509Certificate; const AWorkingPublicKey: IAsymmetricKeyParameter);
begin
  inherited Create();
  FPkixParameters := APkixParameters;
  FValidDate := AValidDate;
  FCertPath := ACertPath;
  FIndex := AIndex;
  FSigningCert := ASigningCert;
  FWorkingPublicKey := AWorkingPublicKey;
end;

function TPkixCertRevocationCheckerParameters.GetPkixParameters: IPkixParameters;
begin
  Result := FPkixParameters;
end;

function TPkixCertRevocationCheckerParameters.GetValidDate: TDateTime;
begin
  Result := FValidDate;
end;

function TPkixCertRevocationCheckerParameters.GetCertPath: IPkixCertPath;
begin
  Result := FCertPath;
end;

function TPkixCertRevocationCheckerParameters.GetIndex: Int32;
begin
  Result := FIndex;
end;

function TPkixCertRevocationCheckerParameters.GetSigningCert: IX509Certificate;
begin
  Result := FSigningCert;
end;

function TPkixCertRevocationCheckerParameters.GetWorkingPublicKey: IAsymmetricKeyParameter;
begin
  Result := FWorkingPublicKey;
end;

end.
