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

unit ClpCryptoServicesRegistrar;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpSecureRandom,
  ClpISecureRandom;

type
  /// <summary>
  /// Provides access to default secure random instances.
  /// </summary>
  TCryptoServicesRegistrar = class sealed(TObject)
  public
    class function GetSecureRandom: ISecureRandom; overload; static;
    class function GetSecureRandom(const ASecureRandom: ISecureRandom): ISecureRandom; overload; static;
  end;

implementation

{ TCryptoServicesRegistrar }

class function TCryptoServicesRegistrar.GetSecureRandom: ISecureRandom;
begin
  Result := TSecureRandom.Create();
end;

class function TCryptoServicesRegistrar.GetSecureRandom(const ASecureRandom: ISecureRandom): ISecureRandom;
begin
  if ASecureRandom <> nil then
    Result := ASecureRandom
  else
    Result := GetSecureRandom();
end;

end.
