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

unit ClpIPemReader;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIPemObjects;

type
  /// <summary>
  /// Interface for PEM reader.
  /// </summary>
  IPemReader = interface(IInterface)
    ['{0139877B-ED23-46C7-BE39-E5010AC26507}']

    function GetReader: TStream;

    /// <summary>
    /// Get the underlying stream reader.
    /// </summary>
    property Reader: TStream read GetReader;

    /// <summary>
    /// Read a PEM object from the stream.
    /// </summary>
    /// <returns>A PEM object, or nil if end of stream</returns>
    function ReadPemObject(): IPemObject;
  end;

implementation

end.
