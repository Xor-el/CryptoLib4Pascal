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

unit MlKemExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIAsymmetricCipherKeyPair,
  ExampleBase,
  PqcExampleUtilities,
  KeyEncodingExampleUtilities;

type
  TMlKemExample = class(TExampleBase)
  private
    procedure RunKemRoundtrip(const AParameterSetName: string);
    procedure RunDerRoundtrip(const AParameterSetName: string);
    procedure RunPemRoundtrip(const AParameterSetName: string);
    procedure RunParameterSetDemos(const AParameterSetName: string);
  public
    procedure Run; override;
  end;

implementation

procedure TMlKemExample.RunKemRoundtrip(const AParameterSetName: string);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TPqcExampleUtilities.RunKemRoundtrip(AParameterSetName, LKp);
end;

procedure TMlKemExample.RunDerRoundtrip(const AParameterSetName: string);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TKeyEncodingExampleUtilities.VerifyDerRoundtrip(LKp, AParameterSetName);
end;

procedure TMlKemExample.RunPemRoundtrip(const AParameterSetName: string);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TKeyEncodingExampleUtilities.VerifyPemRoundtrip(LKp, AParameterSetName);
end;

procedure TMlKemExample.RunParameterSetDemos(const AParameterSetName: string);
begin
  LogWithLineBreak(Format('--- ML-KEM example: encaps/decaps (%s) ---', [AParameterSetName]));
  RunKemRoundtrip(AParameterSetName);

  LogWithLineBreak(Format('--- ML-KEM example: DER round-trip (%s) ---', [AParameterSetName]));
  RunDerRoundtrip(AParameterSetName);

  LogWithLineBreak(Format('--- ML-KEM example: PEM round-trip (%s) ---', [AParameterSetName]));
  RunPemRoundtrip(AParameterSetName);
end;

procedure TMlKemExample.Run;
begin
  RunParameterSetDemos('ML-KEM-768');
  RunParameterSetDemos('ML-KEM-512');
end;

end.
