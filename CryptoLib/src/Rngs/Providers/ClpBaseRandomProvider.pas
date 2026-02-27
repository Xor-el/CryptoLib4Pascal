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

unit ClpBaseRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes,
  ClpIRandomSourceProvider;

type
  /// <summary>
  /// Abstract base class for all random source providers.
  /// Provides a default GetNonZeroBytes implementation that delegates to GetBytes.
  /// Subclasses must override GetBytes, GetIsAvailable, and GetName.
  /// </summary>
  TBaseRandomProvider = class abstract(TInterfacedObject, IRandomSourceProvider)

  public
    procedure GetBytes(const AData: TCryptoLibByteArray); virtual; abstract;

    /// <summary>
    /// Fills AData with non-zero random bytes. Calls GetBytes to fill the array,
    /// then replaces any zero bytes individually. Subclasses may override if a
    /// platform-specific optimized implementation is available.
    /// </summary>
    procedure GetNonZeroBytes(const AData: TCryptoLibByteArray); virtual;

    function GetIsAvailable: Boolean; virtual; abstract;
    function GetName: String; virtual; abstract;

  end;

implementation

{ TBaseRandomProvider }

procedure TBaseRandomProvider.GetNonZeroBytes(const AData: TCryptoLibByteArray);
var
  LI: Int32;
  LTmp: TCryptoLibByteArray;
begin
  GetBytes(AData);
  System.SetLength(LTmp, 1);
  for LI := System.Low(AData) to System.High(AData) do
  begin
    while AData[LI] = 0 do
    begin
      GetBytes(LTmp);
      AData[LI] := LTmp[0];
    end;
  end;
end;

end.
