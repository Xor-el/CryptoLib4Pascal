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

unit ClpBlockCipherBulkUtilities;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIBulkBlockCipher,
  ClpIBulkBlockCipherMode;

type
  /// <summary>
  ///   Shared helpers for bulk block-cipher mode implementations.
  /// </summary>
  TBlockCipherBulkUtilities = class sealed(TObject)
  public
    /// <summary>
    ///   Probe ACipher for IBulkBlockCipher. ABulk is nil on False so
    ///   the caller can blindly assign into an existing field.
    /// </summary>
    class function TryResolveBulkCipher(const ACipher: IBlockCipher;
      out ABulk: IBulkBlockCipher): Boolean; static;

    /// <summary>
    ///   Mode-side sibling of TryResolveBulkCipher; probes AMode for
    ///   IBulkBlockCipherMode. ABulkMode is nil on False.
    /// </summary>
    class function TryResolveBulkCipherMode(const AMode: IBlockCipherMode;
      out ABulkMode: IBulkBlockCipherMode): Boolean; static;
  end;

implementation

{ TBlockCipherBulkUtilities }

class function TBlockCipherBulkUtilities.TryResolveBulkCipher(
  const ACipher: IBlockCipher; out ABulk: IBulkBlockCipher): Boolean;
begin
  ABulk := nil;
  Result := (ACipher <> nil) and Supports(ACipher, IBulkBlockCipher, ABulk);
end;

class function TBlockCipherBulkUtilities.TryResolveBulkCipherMode(
  const AMode: IBlockCipherMode; out ABulkMode: IBulkBlockCipherMode): Boolean;
begin
  ABulkMode := nil;
  Result := (AMode <> nil) and Supports(AMode, IBulkBlockCipherMode, ABulkMode);
end;

end.
