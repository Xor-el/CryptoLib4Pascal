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

unit ClpOpenSslPemWriter;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  Rtti,
  SysUtils,
  ClpIOpenSslPemWriter,
  ClpIPemObjects,
  ClpPemWriter,
  ClpOpenSslMiscPemGenerator,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// General-purpose writer for OpenSSL PEM objects. Inherits from
  /// TPemWriter; accepts any supported object and writes it as PEM by wrapping
  /// it in TMiscPemGenerator.
  /// </summary>
  TOpenSslPemWriter = class(TPemWriter, IOpenSslPemWriter)
  public
    constructor Create(const AWriter: TStream);
    procedure WriteObject(const AObj: TValue); overload;
  end;

implementation

{ TOpenSslPemWriter }

constructor TOpenSslPemWriter.Create(const AWriter: TStream);
begin
  inherited Create(AWriter);
end;

procedure TOpenSslPemWriter.WriteObject(const AObj: TValue);
begin
  try
    inherited WriteObject(TOpenSslMiscPemGenerator.Create(AObj) as IPemObjectGenerator);
  except
    on E: EPemGenerationCryptoLibException do
    begin
      raise;
    end;
  end;
end;

end.
